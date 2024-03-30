# -*- coding: utf-8 -*-
import logging
from enum import IntEnum

import idaapi
import idc
from PyQt5.QtCore import Qt
from ida_nalt import get_imagebase
from idautils import Functions

from requests import Response, HTTPError

from reait.api import re_binary_id, RE_embeddings, RE_nearest_symbols

from revengai.api import RE_collections
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
                                                                flag=Qt.ItemIsSelectable | Qt.ItemIsUserCheckable,
                                                                header=["Source Symbol", "Destination Symbol",
                                                                        "Successful", "Reason",]))

        self.ui.startButton.clicked.connect(self._start_analysis)

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

    def _start_analysis(self):
        inthread(self._auto_analysis)

    def _auto_analysis(self):
        try:
            self._analysis = [0] * len(Analysis)

            inmain(self.ui.startButton.setEnabled, False)
            inmain(self.ui.progressBar.setProperty, "value", 0)

            res: Response = RE_embeddings(fpath=self.path)

            if res.status_code > 299:
                logger.error("Auto Analysis Error: %s", res.json()["error"])
                inmain(Dialog.showError, "Auto Analysis", f"Auto Analysis Error: {res.json()['error']}")
            else:
                embeddings = res.json()

                collections = inmain(self._selected_collections)
                confidence = (float(inmain(self.ui.confidenceSlider.property, "value")) /
                              float(inmain(self.ui.confidenceSlider.property, "maximum")))

                resultsData = []
                max = len(self._functions)
                for idx, func in enumerate(self._functions):
                    idx += 1
                    logger.info("Searching for %s [%d/%d]", func["name"], idx, max)

                    self._analysis[Analysis.TOTAL.value] += 1
                    inmain(self.ui.progressBar.setProperty, "value", idx)

                    fe = next((item for item in embeddings if item["vaddr"] == func["start_addr"]), None)

                    if fe is None:
                        self._analysis[Analysis.SKIPPED.value] += 1
                        resultsData.append((func["name"], "N/A", None, "No Function Embedding Found"))
                    else:
                        try:
                            res = RE_nearest_symbols(embedding=fe["embedding"],
                                                     collections=collections,
                                                     nns=1, ignore_hashes=self._ignore_hashes,
                                                     model_name=self.state.config.get("model"))

                            data = res.json()

                            if len(data) == 0:
                                self._analysis[Analysis.SKIPPED.value] += 1
                                resultsData.append((func["name"], "N/A", None, "No Function Embedding Found"))
                                continue

                            symbol = data[0]

                            if symbol["distance"] >= confidence:
                                logger.info("Found symbol '%s' with a confidence of %f",
                                            symbol['name'], symbol["distance"])

                                # if inmain(IDAUtils.set_name, self.v_addr, symbol['name'])):
                                resultsData.append((func["name"],
                                                    f"{symbol['name']} ({symbol['binary_name']})", None,
                                                    f"Renamed with confidence of '{symbol['distance']}"))
                                # else:
                                #     logger.error("Symbol already exists")
                                #     inmain(Dialog.showError, "Rename Function Error",
                                #            f"Can't rename {func['name']}. Name {symbol['name']} already exists.")
                                #
                                #     self._analysis[Analysis.UNSUCCESSFUL.value] += 1
                                #     resultsData.append((func["name"],
                                #                         f"Can't rename {func['name']}",
                                #                         f"Name {symbol['name']} already exists."))
                                #     continue

                            self._analysis[Analysis.SUCCESSFUL.value] += 1
                        except HTTPError as e:
                            self._analysis[Analysis.UNSUCCESSFUL.value] += 1
                            resultsData.append((func["name"], "N/A", None, e.response.json()["error"]))

                inmain(inmain(self.ui.resultsTable.model).updateData, resultsData)
                inmain(self.ui.resultsTable.resizeColumnsToContents)
        except HTTPError as e:
            inmain(Dialog.showError, "Auto Analysis", f"Auto Analysis Error: {e.response.json()['error']}")
        finally:
            inmain(self.ui.startButton.setEnabled, True)
            inmain(self.ui.progressBar.setProperty, "value", len(self._functions))

    def _filter(self, filter_text):
        table = self.ui.collectionsTable if self.ui.tabWidget.currentIndex() == 0 else self.ui.resultsTable

        for row in range(table.model().rowCount()):
            item = table.model().index(row, 0)
            table.setRowHidden(row, filter_text.lower() not in item.sibling(row, 0).data().lower())

    def _confidence(self, value):
        self.ui.description.setText(f"Confidence: {value:#02d}")

    def _tab_changed(self, index):
        self.ui.confidenceSlider.setEnabled(index == 0)

        if index == 0:
            self._confidence(self.ui.confidenceSlider.sliderPosition())
        else:
            self.ui.description.setText(f"Total Functions Analysed: {self._analysis[Analysis.TOTAL.value]}<br/>"
                                        f"Successful Analyses: {self._analysis[Analysis.SUCCESSFUL.value]}<br/>"
                                        f"Skipped Analyses: {self._analysis[Analysis.SKIPPED.value]}<br/>"
                                        f"Errored Analyses: {self._analysis[Analysis.UNSUCCESSFUL.value]}")

    def _load_collections(self, scope: str = "PUBLIC", page_size: int = 100000, page_number: int = 1):
        try:
            inmain(idaapi.show_wait_box, "HIDECANCEL\nGetting RevEng.AI collections…")

            inmain(self.ui.startButton.setEnabled, False)

            res: Response = RE_collections(scope, page_size, page_number)

            collections = []
            for collection in res.json()["collections"]:
                collections.append([collection["collection_name"], None])

            inmain(inmain(self.ui.collectionsTable.model).updateData, collections)
            inmain(self.ui.collectionsTable.resizeColumnsToContents)
        except HTTPError as e:
            inmain(idaapi.hide_wait_box)
            inmain(Dialog.showError, "Auto Analysis", f"Auto Analysis Error: {e.response.json()['error']}")
        else:
            self._auto_analysis()
            inmain(idaapi.hide_wait_box)

    def _selected_collections(self):
        model = self.ui.collectionsTable.model()

        regex = []
        for idx in range(self.ui.collectionsTable.model().rowCount()):
            if model.index(idx, 1).data(Qt.CheckStateRole) == Qt.Checked:
                regex.append(model.index(idx, 0).data(Qt.DisplayRole))

        return regex
