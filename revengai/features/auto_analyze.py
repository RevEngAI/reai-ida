# -*- coding: utf-8 -*-

from enum import IntEnum

import idc
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog
from ida_nalt import get_imagebase
from idautils import Functions
from requests import Response, HTTPError, post

from reait.api import RE_embeddings, binary_id, RE_nearest_symbols, reveng_req
from revengai.models.checkable_model import RevEngCheckableTableModel
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.models.table_model import RevEngTableModel
from revengai.ui.auto_analysis_panel import Ui_AutoAnalysisPanel


class Analysis(IntEnum):
    TOTAL = 0
    SKIPPED = 1
    UNSUCCESSFUL = 2
    SUCCESSFUL = 3


class AutoAnalysisDialog(QDialog):
    def __init__(self, state: RevEngState, fpath: str):
        QDialog.__init__(self)

        self.path = fpath
        self.state = state

        self._ignore_hashes = [binary_id(self.path)]

        self.ui = Ui_AutoAnalysisPanel()
        self.ui.setupUi(self)

        self.ui.collectionsTable.setModel(RevEngCheckableTableModel(header=["Collection Name", "Include",],
                                                                    data=[], columns=[1], parent=self))

        self.ui.resultsTable.setModel(RevEngTableModel(data=[], parent=self,
                                                       header=["Source Symbol", "Destination Symbol",
                                                               "Successful", "Reason",]))

        self.ui.startButton.clicked.connect(self.auto_analysis)

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
        self.load_collections()

    def auto_analysis(self):
        try:
            self._analysis = [0] * len(Analysis)

            self.ui.startButton.setEnabled(False)
            self.ui.progressBar.setProperty("value", 0)

            res: Response = RE_embeddings(fpath=self.path)

            if res.status_code > 299:
                Dialog.showError("Auto Analysis",
                                 f"Auto Analysis Error: {res.json()['error']}")
            else:
                embeddings = res.json()

                resultsData = []
                confidence = (float(self.ui.confidenceSlider.property("value")) /
                              float(self.ui.confidenceSlider.property("maximum")))

                for idx, func in enumerate(self._functions):
                    self._analysis[Analysis.TOTAL.value] += 1
                    self.ui.progressBar.setProperty("value", idx)

                    fe = next((item for item in embeddings if item["vaddr"] == func["start_addr"]), None)

                    if fe is None:
                        self._analysis[Analysis.SKIPPED.value] += 1
                        resultsData.append((func["name"], "N/A", "No Function Embedding Found"))
                    else:
                        try:
                            res = RE_nearest_symbols(embedding=fe["embedding"],
                                                     collections=self._selected_collections(),
                                                     nns=1, ignore_hashes=self._ignore_hashes,
                                                     model_name=self.state.config.get("model"))

                            data = res.json()

                            if len(data) == 0:
                                self._analysis[Analysis.SKIPPED.value] += 1
                                resultsData.append((func["name"], "N/A", "No Function Embedding Found"))
                                continue

                            symbol = data[0]

                            if symbol["distance"] >= confidence:
                                # if idc.set_name(self.v_addr, item['name'],
                                #                 ida_name.SN_FORCE | ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
                                resultsData.append((func["name"],
                                                    f"{symbol['name']} ({symbol['binary_name']})",
                                                    f"Renamed with confidence of {symbol['distance']}"))
                                # else:
                                #     Dialog.showError("Rename Function Error", "Symbol already exists.")

                            self._analysis[Analysis.SUCCESSFUL.value] += 1
                        except HTTPError as e:
                            self._analysis[Analysis.UNSUCCESSFUL.value] += 1
                            resultsData.append((func["name"], "N/A", e.response.text))

                self.ui.resultsTable.model().updateData(resultsData)
                self.ui.resultsTable.resizeColumnsToContents()
        except HTTPError as e:
            Dialog.showError("Auto Analysis",
                             f"Auto Analysis Error: {e.response.json()['error']}")
        finally:
            self.ui.startButton.setEnabled(True)
            self.ui.progressBar.setProperty("value", len(self._functions))

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

    def load_collections(self, scope: str = "PUBLIC", page_size: int = 100000, page_number: int = 1):
        try:
            self.ui.startButton.setEnabled(False)

            res: Response = reveng_req(post, "collections",
                                       json_data={"scope": scope,
                                                  "page_size": page_size,
                                                  "page_number": page_number})

            res.raise_for_status()

            collections = []
            for collection in res.json()["collections"]:
                collections.append([collection["collection_name"], None])

            self.ui.collectionsTable.model().updateData(collections)
            self.ui.collectionsTable.resizeColumnsToContents()
        except HTTPError as e:
            Dialog.showError("Auto Analysis",
                             f"Auto Analysis Error: {e.response.json()['error']}")
        finally:
            self.auto_analysis()

    def _selected_collections(self):
        model = self.ui.collectionsTable.model()

        regex = []
        for idx in range(self.ui.collectionsTable.model().rowCount()):
            if model.index(idx, 1).data(Qt.CheckStateRole) == Qt.Checked:
                regex.append(model.index(idx, 0).data(Qt.DisplayRole))

        return regex
