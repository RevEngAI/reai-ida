import ida_name
import idc
from PyQt5.QtWidgets import QDialog
from requests import Response, HTTPError, post

from reait.api import RE_embeddings, binary_id, RE_nearest_symbols, reveng_req
from revengai.checkable_model import RevEngCheckableTableModel
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.ui.auto_analysis_panel import Ui_AutoAnalysisPanel


class AutoAnalysisDialog(QDialog):
    def __init__(self, state: RevEngState, fpath: str):
        QDialog.__init__(self)

        self.path = fpath
        self.state = state

        self._ignore_hashes = [binary_id(self.path)]

        self.ui = Ui_AutoAnalysisPanel()
        self.ui.setupUi(self)

        self.ui.collectionsTable.setModel(RevEngCheckableTableModel(header=["Collection Name", "Include"],
                                                                    data=[], columns=[1], parent=self))

        # self.ui.resultsTable.setModel(RevEngTableModel([], ["Source Symbol", "Destination Symbol", "Successful", "Reason"], self))

        self.ui.startButton.clicked.connect(self.analyze)

        self.ui.resultsFilter.textChanged.connect(self._filter)
        self.ui.collectionsFilter.textChanged.connect(self._filter)

        self.ui.confidenceSlider.valueChanged.connect(self._confidence)
        self.ui.tabWidget.tabBarClicked.connect(self._tabChanged)
        self._confidence(self.ui.confidenceSlider.sliderPosition())
        self._functions = []

        ea = idc.here()
        if idc.get_func_name(ea) == "":
            ea = idc.get_next_func(ea)

        while ea != idc.BADADDR:
            func_name = idc.get_func_name(ea)
            func_end = idc.get_func_attr(ea, idc.FUNCATTR_END)
            self._functions.append({"name": func_name, "start_addr": ea, "end_addr": func_end})
            ea = idc.get_next_func(ea)

        self.ui.progressBar.setProperty("maximum", len(self._functions))

    def showEvent(self, event):
        super(AutoAnalysisDialog, self).showEvent(event)
        self.analyze()

    def analyze(self):
        try:
            self.ui.startButton.setEnabled(False)
            self.ui.progressBar.setProperty("value", 0)

            res: Response = reveng_req(post, "collections",
                                       json_data={"scope": "PUBLIC",
                                                  "page_size": 1000,
                                                  "page_number": 1})
            collections = []
            for collection in res.json()["collections"]:
                collections.append([collection["collection_name"], ""])

            self.ui.collectionsTable.model().updateData(collections)

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
                    self.ui.progressBar.setProperty("value", idx)

                    fe = next((item for item in embeddings if item["vaddr"] == func["start_addr"]), None)

                    if not fe:
                        resultsData.append((func["name"], "N/A", "No Function Embedding Found"))
                    else:
                        try:
                            res = RE_nearest_symbols(embedding=fe["embedding"],
                                                     nns=1, ignore_hashes=self._ignore_hashes,
                                                     model_name=self.state.config.base.config.get("model"))

                            data = res.json()

                            if len(data) == 0:
                                continue

                            symbol = data[0]

                            if symbol["distance"] >= confidence:
                                # if idc.set_name(self.v_addr, item['name'],
                                #                 ida_name.SN_FORCE | ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
                                resultsData.append((f"{symbol['name']} ({symbol['binary_name']})", True,
                                                    f"Renamed with confidence of {symbol['distance']}"))
                                # else:
                                #     Dialog.showError("Rename Function Error", "Symbol already exists.")

                            # print(resultsData)
                        except HTTPError as e:
                            resultsData.append((func["name"], "N/A", e.response.text))
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
            match = filter_text.lower() not in item.sibling(row, 0).data().lower()
            table.setRowHidden(row, match)

    def _confidence(self, value):
        self.ui.description.setText(f"Confidence: {value:#02d}")

    def _tabChanged(self, index):
        self.ui.confidenceSlider.setEnabled(index == 0)
