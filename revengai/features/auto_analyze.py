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

from reait.api import re_binary_id, RE_embeddings, RE_nearest_symbols

from revengai.api import RE_collections, RE_collections_count
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
    def __init__(self, state: RevEngState, fpath: str):
        BaseDialog.__init__(self, state, fpath)

        self._ignore_hashes = [re_binary_id(self.path)]

        self.ui = Ui_AutoAnalysisPanel()
        self.ui.setupUi(self)

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

        base_addr = get_imagebase()

        for func_ea in Functions():
            self._functions.append({"name": idc.get_func_name(func_ea),
                                    "start_addr": (idc.get_func_attr(func_ea, idc.FUNCATTR_START) - base_addr),
                                    "end_addr": (idc.get_func_attr(func_ea, idc.FUNCATTR_END) - base_addr)})

        self.ui.progressBar.setProperty("maximum", len(self._functions))

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
            inmain(self.ui.progressBar.setProperty, "value", 0)

            res: Response = RE_embeddings(self.path, self.state.config.get("binary_id", 0))

            if res.status_code > 299:
                logger.error("Auto Analysis Error: %s", res.json()["error"])
                inmain(Dialog.showError, "Auto Analysis", f"Auto Analysis Error: {res.json()['error']}")
            else:
                embeddings = res.json()

                collections = inmain(self._selected_collections)
                confidence = 1 - (int(inmain(self.ui.confidenceSlider.property, "value")) /
                                  int(inmain(self.ui.confidenceSlider.property, "maximum")))

                resultsData = []
                nb_func = len(self._functions)
                self._analysis[Analysis.TOTAL.value] = nb_func

                for idx, func in enumerate(self._functions):
                    idx += 1
                    logger.info("Searching for %s [%d/%d]", func["name"], idx, nb_func)

                    inmain(self.ui.progressBar.setProperty, "value", idx)

                    fe = next((item for item in embeddings if item["vaddr"] == func["start_addr"]), None)

                    if fe is None:
                        self._analysis[Analysis.SKIPPED.value] += 1
                        resultsData.append((func["name"], "N/A", None, "No Function Embedding Found"))
                    else:
                        try:
                            res = RE_nearest_symbols(embedding=fe["embedding"],
                                                     distance=confidence, collections=collections,
                                                     nns=1, ignore_hashes=self._ignore_hashes,
                                                     model_name=self.state.config.get("model"))

                            data = res.json()

                            if len(data) == 0:
                                self._analysis[Analysis.SKIPPED.value] += 1
                                resultsData.append((func["name"], "N/A", None, "No Function Embedding Found"))
                                continue

                            symbol = data[0]

                            symbol["func_name"] = func["name"]
                            symbol["func_addr"] = func["start_addr"]

                            logger.info("Found symbol '%s' with a confidence of %f",
                                        symbol['name'], symbol["distance"])

                            item = QStandardItem()

                            item.setData(symbol)
                            item.setCheckState(Qt.Checked)
                            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)

                            resultsData.append((func["name"],
                                                f"{symbol['name']} ({symbol['binary_name']})", item,
                                                f"Can be renamed with confidence of '{symbol['distance']}"))

                            self._analysis[Analysis.SUCCESSFUL.value] += 1
                        except HTTPError as e:
                            self._analysis[Analysis.UNSUCCESSFUL.value] += 1
                            resultsData.append((func["name"], "N/A", None, e.response.json()["error"]))

                inmain(inmain(self.ui.resultsTable.model).updateData, resultsData)
                inmain(self.ui.resultsTable.resizeColumnsToContents)
        except HTTPError as e:
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

    def _confidence(self, value) -> None:
        if self.ui.tabWidget.currentIndex() == 0:
            self.ui.description.setText(f"Confidence: {value:#02d}")

    def _tab_changed(self, index) -> None:
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

    def _load_collections(self, scope: str = "PUBLIC", page_size: int = 100000, page_number: int = 1) -> None:
        try:
            inmain(idaapi.show_wait_box, "HIDECANCEL\nGetting RevEng.AI collections…")

            inmain(self.ui.fetchButton.setEnabled, False)

            res: Response = RE_collections_count(scope)

            res = RE_collections(scope, min(page_size, res.json()["count"]), page_number)

            collections = []
            for collection in res.json()["collections"]:
                collections.append([collection["collection_name"], None])

            inmain(inmain(self.ui.collectionsTable.model).updateData, collections)
            inmain(self.ui.collectionsTable.resizeColumnsToContents)
        except HTTPError as e:
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
            
            if IDAUtils.set_name(symbol["func_addr"], symbol['name']):
                logger.info(f"Renowned {symbol['func_name']} in {symbol['name']} "
                            f"with confidence of '{symbol['distance']}.")
            else:
                logger.warning("Symbol name %s already exists.", symbol["name"])
                idc.warning(f"Can't rename {symbol['func_name']}. Name {symbol['name']} already exists.")
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
