# -*- coding: utf-8 -*-
import logging
from enum import IntEnum

import idaapi
import idc
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItem, QCursor
from PyQt5.QtWidgets import QMenu
from ida_nalt import get_imagebase
from idautils import Functions

from requests import Response, HTTPError

from reait.api import re_binary_id, RE_nearest_symbols_batch

from revengai.api import RE_collections, RE_analyze_functions
from revengai.features import BaseDialog
from revengai.misc.utils import IDAUtils
from revengai.misc.qtutils import inthread, inmain
from revengai.models.checkable_model import RevEngCheckableTableModel
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.ui.auto_analysis_panel import Ui_AutoAnalysisPanel


logger = logging.getLogger("REAI")


class Analysis(IntEnum):
    TOTAL = 0
    SKIPPED = 1
    UNSUCCESSFUL = 2
    SUCCESSFUL = 3


class AutoAnalysisDialog(BaseDialog):
    _page_size: int = 50
    _scope: str = "PUBLIC"

    def __init__(self, state: RevEngState, fpath: str):
        BaseDialog.__init__(self, state, fpath)

        self._ignore_hashes = [re_binary_id(self.path)]

        self.ui = Ui_AutoAnalysisPanel()
        self.ui.setupUi(self)

        self.ui.collectionsTable.verticalScrollBar().valueChanged.connect(self._on_scroll)
        self.ui.collectionsTable.setModel(RevEngCheckableTableModel(header=["Collection Name", "Include",],
                                                                    data=[], columns=[1], parent=self))

        self.ui.resultsTable.setModel(RevEngCheckableTableModel(data=[], parent=self, columns=[2],
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

        self._base_addr = get_imagebase()

        for func_ea in Functions():
            if IDAUtils.is_in_valid_segment(idc.get_func_attr(func_ea, idc.FUNCATTR_START)):
                self._functions.append({"name": idc.get_func_name(func_ea),
                                        "start_addr": (idc.get_func_attr(func_ea, idc.FUNCATTR_START) - self._base_addr),
                                        "end_addr": (idc.get_func_attr(func_ea, idc.FUNCATTR_END) - self._base_addr)})

        self.ui.progressBar.setProperty("maximum", 2 + (len(self._functions) << 1))

    def showEvent(self, event):
        super(AutoAnalysisDialog, self).showEvent(event)
        inthread(self._load_collections)

    def _table_menu(self) -> None:
        selected = self.ui.resultsTable.selectedIndexes()

        if selected and self.ui.renameButton.isEnabled() and \
                isinstance(self.ui.resultsTable.selectionModel().selectedRows(column=2)[0].data(), QStandardItem):
            menu = QMenu()
            renameAction = menu.addAction(self.ui.renameButton.text())
            renameAction.triggered.connect(lambda: self._rename_function(selected))
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

            res: Response = RE_analyze_functions(self.path, self.state.config.get("binary_id", 0))

            functions = res.json()["functions"]

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

                fe = next((function for function in functions
                           if function["function_vaddr"] == func["start_addr"]), None)

                if fe:
                    function_ids.append(fe["function_id"])

            pos = 1 + nb_func
            res = RE_nearest_symbols_batch(function_ids=function_ids,
                                           distance=confidence, collections=collections,
                                           nns=1, ignore_hashes=self._ignore_hashes,
                                           model_name=self.state.config.get("model"))

            inmain(self.ui.progressBar.setProperty, "value", pos)

            symbols = []
            for symbol in res.json():
                func = next((function for function in functions
                             if function["function_id"] == symbol["origin_function_id"]), None)

                if func:
                    symbol["func_addr"] = func["function_vaddr"]
                    symbols.append(symbol)

            pos += 2
            inmain(self.ui.progressBar.setProperty, "value", pos)

            for idx, function in enumerate(self._functions):
                inmain(self.ui.progressBar.setProperty, "value", idx + pos)

                sym = next((symbol for symbol in symbols if symbol["func_addr"] == function["start_addr"]), None)
                if not sym:
                    self._analysis[Analysis.SKIPPED.value] += 1
                    resultsData.append((function["name"], "N/A", None, "No Function Symbol Found"))
                else:
                    self._analysis[Analysis.SUCCESSFUL.value] += 1
                    
                    sym["func_name"] = function["name"]

                    logger.info("Found symbol '%s' with a confidence of %f",
                                sym["nearest_neighbor_function_name"], sym["confidence"])

                    item = QStandardItem()

                    item.setData(sym)
                    item.setCheckState(Qt.Checked)
                    item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)

                    resultsData.append((sym["func_name"],
                                        f"{sym['nearest_neighbor_function_name']} "
                                        f"({sym['nearest_neighbor_binary_name']})", item,
                                        f"Can be renamed with confidence of '{sym['confidence']}"))

            inmain(inmain(self.ui.resultsTable.model).fill_table, resultsData)
            inmain(self.ui.resultsTable.resizeColumnsToContents)
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

    def _load_collections(self, page_number: int = 1) -> None:
        try:
            inmain(idaapi.show_wait_box, "HIDECANCEL\nGetting RevEng.AI collections…")

            inmain(self.ui.fetchButton.setEnabled, False)

            res = RE_collections(self._scope, self._page_size, page_number)

            collections: list = []
            for child in inmain(self.ui.collectionsTable.model).get_data:
                collections.append(child)

            for collection in res.json()["collections"]:
                collections.append([collection["collection_name"], None])

            inmain(inmain(self.ui.collectionsTable.model).fill_table, collections)
            inmain(self.ui.collectionsTable.resizeColumnsToContents)
        except HTTPError as e:
            logger.error("Getting collections failed for page: %d. Reason: %s", page_number, e)

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
            
            if IDAUtils.set_name(symbol["func_addr"], symbol["nearest_neighbor_function_name"]):
                inthread(self._set_function_renamed, symbol["func_addr"], symbol["nearest_neighbor_function_name"])

                logger.info("Renowned %s in %s with confidence of '%s",
                            symbol["func_name"], symbol["nearest_neighbor_function_name"], symbol["confidence"])
            else:
                logger.warning("Symbol name %s already exists", symbol["nearest_neighbor_function_name"])
                idc.warning(f"Can't rename {symbol['func_name']}. "
                            f"Name {symbol['nearest_neighbor_function_name']} already exists.")
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

    def _on_scroll(self, value: int) -> None:
        if len(self.ui.collectionsFilter.text()) == 0 and \
                value / self.ui.collectionsTable.verticalScrollBar().maximum() >= .75:
            inthread(self._load_collections,
                     1 + round(self.ui.collectionsTable.model().rowCount() / self._page_size))
