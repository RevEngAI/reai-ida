# -*- coding: utf-8 -*-
import logging
from enum import IntEnum

import idaapi
import idc
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItem, QCursor
from PyQt5.QtWidgets import QMenu
from ida_nalt import retrieve_input_file_sha256
from idautils import Functions

from requests import Response, HTTPError

from reait.api import RE_nearest_symbols_batch

from revengai.api import RE_quick_search
from revengai.features import BaseDialog
from revengai.misc.utils import IDAUtils
from revengai.misc.qtutils import inthread, inmain
from revengai.models.checkable_model import RevEngCheckableTableModel
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.models.table_model import TableItem
from revengai.ui.auto_analysis_panel import Ui_AutoAnalysisPanel

logger = logging.getLogger("REAI")


class Analysis(IntEnum):
    TOTAL = 0
    SKIPPED = 1
    UNSUCCESSFUL = 2
    SUCCESSFUL = 3


class AutoAnalysisDialog(BaseDialog):
    def __init__(self, state: RevEngState, fpath: str):
        BaseDialog.__init__(self, state, fpath)

        self._ignore_hashes = [retrieve_input_file_sha256().hex()]

        self.ui = Ui_AutoAnalysisPanel()
        self.ui.setupUi(self)

        self.ui.collectionsTable.setModel(RevEngCheckableTableModel(data=[], columns=[1], parent=self,
                                                                    header=["Collection Name", "Include",]))

        self.ui.resultsTable.setModel(RevEngCheckableTableModel(data=[], columns=[2], parent=self,
                                                                flag=(Qt.ItemIsSelectable | Qt.ItemIsUserCheckable),
                                                                header=["Source Symbol", "Destination Symbol",
                                                                        "Successful", "Reason",]))

        self.ui.resultsTable.customContextMenuRequested.connect(self._table_menu)

        self.ui.fetchButton.clicked.connect(self._start_analysis)
        self.ui.renameButton.clicked.connect(self._rename_function)

        self.ui.resultsFilter.textChanged.connect(self._filter)
        self.ui.collectionsFilter.textChanged.connect(self._filter)

        self.ui.confidenceSlider.valueChanged.connect(self._confidence)
        self.ui.tabWidget.tabBarClicked.connect(self._tab_changed)

        self._confidence(self.ui.confidenceSlider.sliderPosition())

        self._functions = []
        self._analysis = [0] * len(Analysis)

        for func_ea in Functions():
            start_addr = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
            if IDAUtils.is_in_valid_segment(start_addr):
                self._functions.append({"name": IDAUtils.get_demangled_func_name(func_ea),
                                        "start_addr": (start_addr - self.base_addr),
                                        "end_addr": (idc.get_func_attr(func_ea, idc.FUNCATTR_END) - self.base_addr),
                                        })

        self.ui.progressBar.setProperty("maximum", 2 + (len(self._functions) << 1))

    def showEvent(self, event):
        super(AutoAnalysisDialog, self).showEvent(event)

        inthread(self._load_collections)

    def closeEvent(self, event):
        super(AutoAnalysisDialog, self).closeEvent(event)

        self._analysis.clear()
        self._functions.clear()

    def _table_menu(self) -> None:
        selected = self.ui.resultsTable.selectedIndexes()

        if selected and self.ui.renameButton.isEnabled() and isinstance(selected[2].data(), QStandardItem):
            menu = QMenu()
            renameAction = menu.addAction(self.ui.renameButton.text())
            renameAction.triggered.connect(lambda: self._rename_function(selected))

            breakdownAction = menu.addAction("View Function Breakdown")
            breakdownAction.triggered.connect(lambda: self._function_breakdown(selected[2].data().data()["function_id"]))

            menu.exec_(QCursor.pos())

    def _start_analysis(self) -> None:
        inthread(self._auto_analysis)

    def _auto_analysis(self) -> None:
        try:
            self._analysis = [0] * len(Analysis)

            inmain(self.ui.fetchButton.setEnabled, False)
            inmain(self.ui.renameButton.setEnabled, False)
            inmain(self.ui.confidenceSlider.setEnabled, False)
            inmain(self.ui.progressBar.setProperty, "value", 1)

            if not self.analyzed_functions or len(self.analyzed_functions) == 0:
                self._get_analyze_functions()

            collections = inmain(self._selected_collections)
            confidence = 1 - (int(inmain(self.ui.confidenceSlider.property, "value")) /
                              int(inmain(self.ui.confidenceSlider.property, "maximum")))

            resultsData = []
            function_ids = []
            nb_func = len(self._functions)
            self._analysis[Analysis.TOTAL.value] = nb_func

            for idx, func in enumerate(self._functions):
                idx += 1
                logger.info("Searching for %s [%d/%d]", func["name"], idx, nb_func)

                inmain(self.ui.progressBar.setProperty, "value", idx)

                function_id = self.analyzed_functions.get(func["start_addr"], None)

                if function_id:
                    function_ids.append(function_id)

            pos = 1 + nb_func

            inmain(self.ui.progressBar.setProperty, "value", pos)

            for chunk in AutoAnalysisDialog._divide_chunks(function_ids):
                res = RE_nearest_symbols_batch(function_ids=chunk,
                                               distance=confidence, collections=collections,
                                               nns=1, ignore_hashes=self._ignore_hashes)

                symbols = []

                for function_id, symbol in res.json()["function_matches"].items():
                    func_addr = next((func_addr for func_addr, func_id in self.analyzed_functions.items()
                                      if function_id == str(func_id)), None)

                    if func_addr and len(symbol.values()):
                        sym = next(iter(symbol.values()))
                        sym["function_addr"] = func_addr
                        sym["function_id"] = next(iter(symbol))
                        symbols.append(sym)

                pos += len(chunk)
                inmain(self.ui.progressBar.setProperty, "value", pos)

                for function in self._functions:
                    symbol = next((sym for sym in symbols if sym["function_addr"] == function["start_addr"]), None)

                    if symbol:
                        self._analysis[Analysis.SUCCESSFUL.value] += 1

                        symbol["org_func_name"] = function["name"]

                        logger.info("Found symbol '%s' with a confidence level of '%s",
                                    symbol["function_name"], str(symbol["confidence"]))

                        item = QStandardItem()

                        item.setData(symbol)
                        item.setCheckState(Qt.Checked)
                        item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)

                        resultsData.append((symbol["org_func_name"],
                                            f"{symbol['function_name']} ({symbol['binary_name']})", item,
                                            "Can be renamed with a confidence level of "
                                            f"{float(str(symbol['confidence'])[:6]) * 100}%"))

            for idx, func in enumerate(self._functions):
                if not any(data[0] == func["name"] for data in resultsData):
                    self._analysis[Analysis.SKIPPED.value] += 1
                    resultsData.insert(idx, (func["name"], "N/A", None, "No Function Symbol Found"))

            inmain(inmain(self.ui.resultsTable.model).fill_table, resultsData)

            width: int = inmain(self.ui.resultsTable.width)

            inmain(self.ui.resultsTable.setColumnWidth, 0, width * .2)
            inmain(self.ui.resultsTable.setColumnWidth, 1, width * .4)
            inmain(self.ui.resultsTable.setColumnWidth, 2, width * .1)
            inmain(self.ui.resultsTable.setColumnWidth, 3, width * .3)
        except HTTPError as e:
            logger.error("Fetching auto analysis failed. Reason: %s", e)
            inmain(Dialog.showError, "Auto Analysis", f"Auto Analysis Error: {e.response.json()['error']}")
        finally:
            inmain(self._tab_changed, 1)
            inmain(self.ui.tabWidget.setCurrentIndex, 1)
            inmain(self.ui.fetchButton.setEnabled, True)
            inmain(self.ui.confidenceSlider.setEnabled, True)
            inmain(self.ui.progressBar.setProperty, "value", 0)

    def _filter(self, filter_text) -> None:
        table = self.ui.collectionsTable if self.ui.tabWidget.currentIndex() == 0 else self.ui.resultsTable

        for row in range(table.model().rowCount()):
            item = table.model().index(row, 0)
            table.setRowHidden(row, filter_text.lower() not in item.sibling(row, 0).data().lower())

    def _confidence(self, value: int) -> None:
        if self.ui.tabWidget.currentIndex() == 0:
            self.ui.description.setText(f"Confidence: {value:#02d}")

    def _tab_changed(self, index: int) -> None:
        if index == 0:
            self.ui.description.setVisible(True)
            self.ui.renameButton.setEnabled(False)
            self.ui.description.setText(f"Confidence: {self.ui.confidenceSlider.sliderPosition():#02d}")
        else:
            self.ui.description.setVisible(self._analysis[Analysis.TOTAL.value] > 0)
            self.ui.renameButton.setEnabled(self._analysis[Analysis.SUCCESSFUL.value] > 0)
            self.ui.description.setText(f"Total Functions Analysed: {self._analysis[Analysis.TOTAL.value]}<br/>"
                                        f"Successful Analyses: {self._analysis[Analysis.SUCCESSFUL.value]}<br/>"
                                        f"Skipped Analyses: {self._analysis[Analysis.SKIPPED.value]}<br/>"
                                        f"Errored Analyses: {self._analysis[Analysis.UNSUCCESSFUL.value]}")

    def _load_collections(self) -> None:
        try:
            inmain(idaapi.show_wait_box, "HIDECANCEL\nGetting RevEng.AI collections…")

            inmain(self.ui.fetchButton.setEnabled, False)

            res: Response = RE_quick_search(self.state.config.get("model"))

            collections = []

            for collection in res.json()["collections"]:
                collections.append((TableItem(collection["collection_name"],
                                              "lock.png"
                                              if collection["collection_scope"] == "PRIVATE"
                                              else "unlock.png"),
                                    None,))

            inmain(inmain(self.ui.collectionsTable.model).fill_table, collections)
            inmain(self.ui.collectionsTable.setColumnWidth, 0, inmain(self.ui.collectionsTable.width) * .9)
        except HTTPError as e:
            logger.error("Getting collections failed. Reason: %s", e)

            inmain(idaapi.hide_wait_box)
            inmain(Dialog.showError, "Auto Analysis", f"Auto Analysis Error: {e.response.json()['error']}")
        else:
            inmain(idaapi.hide_wait_box)
        finally:
            inmain(self._tab_changed, 0)
            inmain(self.ui.tabWidget.setCurrentIndex, 0)
            inmain(self.ui.fetchButton.setEnabled, True)
            inmain(self.ui.fetchButton.setFocus)

    def _rename_function(self, selected: list = None) -> None:
        if selected:
            symbol = selected[2].data().data()

            if IDAUtils.set_name(symbol["function_addr"] + self.base_addr, symbol["function_name"]):
                inthread(self._set_function_renamed, symbol["function_addr"], symbol["function_name"])

                logger.info("Renowned %s in %s with confidence of '%s",
                            symbol["org_func_name"], symbol["function_name"], symbol["confidence"])
            else:
                logger.warning("Symbol name %s already exists", symbol["function_name"])
                idc.warning(f"Can't rename {symbol['org_func_name']}. Name {symbol['function_name']} already exists.")
        else:
            model = self.ui.resultsTable.model()

            for idx in range(model.rowCount()):
                if isinstance(model.index(idx, 2).data(), QStandardItem) and \
                        model.index(idx, 2).data().checkState() == Qt.Checked:
                    self._rename_function([None, None, model.index(idx, 2), None])

    def _selected_collections(self) -> list:
        model = self.ui.collectionsTable.model()

        regex = []
        for idx in range(model.rowCount()):
            if model.index(idx, 1).data(Qt.CheckStateRole) == Qt.Checked:
                regex.append(model.index(idx, 0).data(Qt.DisplayRole))

        return regex

    # Yield successive n-sized
    # chunks from l.
    @staticmethod
    def _divide_chunks(l: list, n: int = 50) -> list:
        # looping till length l
        for idx in range(0, len(l), n):
            yield l[idx:idx + n]
