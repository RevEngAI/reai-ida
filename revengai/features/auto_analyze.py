# -*- coding: utf-8 -*-
import logging
from os import cpu_count
from concurrent.futures import as_completed, ThreadPoolExecutor, CancelledError
from re import sub
from enum import IntEnum

import idc
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QMenu
from idaapi import hide_wait_box, show_wait_box, user_cancelled
from idautils import Functions

from requests import Response, HTTPError, RequestException

from reait.api import RE_nearest_symbols_batch

from revengai.api import RE_collection_search
from revengai.features import BaseDialog
from revengai.misc.utils import IDAUtils
from revengai.misc.qtutils import inthread, inmain
from revengai.models import CheckableItem, IconItem, SimpleItem
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

        self.ui = Ui_AutoAnalysisPanel()
        self.ui.setupUi(self)

        self.ui.layoutFilter.register_cb(self._callback)

        self.ui.collectionsFilter.textChanged.connect(self._filter)
        self.ui.collectionsTable.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.ui.collectionsTable.setModel(RevEngCheckableTableModel(data=[], columns=[1], parent=self,
                                                                    header=["Collection Name", "Include",]))

        self.ui.collectionsTable.model().dataChanged.connect(self._state_change)

        self.ui.resultsFilter.textChanged.connect(self._filter)
        self.ui.resultsTable.customContextMenuRequested.connect(self._table_menu)
        self.ui.resultsTable.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.ui.resultsTable.setModel(RevEngCheckableTableModel(data=[], columns=[2], parent=self,
                                                                header=["Function Name", "Destination Function Name",
                                                                        "Successful", "Reason",]))

        self.ui.fetchButton.clicked.connect(self._start_analysis)
        self.ui.renameButton.clicked.connect(self._rename_functions)


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

        inthread(self._search_collection)

    def closeEvent(self, event):
        super(AutoAnalysisDialog, self).closeEvent(event)

        self._analysis.clear()
        self._functions.clear()

    def _table_menu(self) -> None:
        rows = sorted(set(index.row() for index in self.ui.resultsTable.selectedIndexes()))
        selected = self.ui.resultsTable.model().get_data(rows[0])

        if selected and self.ui.renameButton.isEnabled() and isinstance(selected[2], CheckableItem):
            menu = QMenu()
            renameAction = menu.addAction(self.ui.renameButton.text())
            renameAction.triggered.connect(lambda: self._rename_function(selected))

            func_id = selected[2].data["nearest_neighbor_id"]
            breakdownAction = menu.addAction("View Function Breakdown")
            breakdownAction.triggered.connect(lambda: self._function_breakdown(func_id))

            # summariesAction = menu.addAction("Generate AI Summaries")
            # summariesAction.triggered.connect(lambda: self._generate_summaries(func_id))

            menu.exec_(QCursor.pos())

    def _start_analysis(self) -> None:
        inthread(self._auto_analysis)

    def _auto_analysis(self) -> None:
        try:
            inmain(show_wait_box, "Getting results…")

            self._analysis = [0,] * len(Analysis)

            inmain(self.ui.fetchButton.setEnabled, False)
            inmain(self.ui.renameButton.setEnabled, False)
            inmain(self.ui.confidenceSlider.setEnabled, False)
            inmain(self.ui.progressBar.setProperty, "value", 1)

            inmain(inmain(self.ui.resultsTable.model).fill_table, [])
            inmain(self._tab_changed, inmain(self.ui.tabWidget.currentIndex))

            if not self.analyzed_functions or len(self.analyzed_functions) == 0:
                self._get_analyze_functions()

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
                else:
                    self._analysis[Analysis.SKIPPED.value] += 1
                    resultsData.append((func["name"], "N/A", None, "No Similar Function Found",))

            pos = 1 + nb_func

            inmain(self.ui.progressBar.setProperty, "value", pos)

            max_workers = 1
            if self.state.project_cfg.get("parallelize_query") and not inmain(user_cancelled):
                max_workers += min(cpu_count(), nb_func // self.state.project_cfg.get("ann_chunk_size"))

            # Launch parallel tasks
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                collections = inmain(self._selected_collections)
                distance = 1.0 - (int(inmain(self.ui.confidenceSlider.property, "value")) /
                                  int(inmain(self.ui.confidenceSlider.property, "maximum")))

                def worker(chunk: list[int]) -> any:
                    try:
                        if inmain(user_cancelled):
                            raise CancelledError("Auto analysis cancelled")

                        return RE_nearest_symbols_batch(function_ids=chunk, distance=distance,
                                                        collections=collections, nns=1).json()["function_matches"]
                    except Exception as ex:
                        return ex

                # Start the ANN batch operations and mark each future with its chunk
                futures = {executor.submit(worker, chunk): chunk
                           for chunk in AutoAnalysisDialog._divide_chunks(function_ids,
                                                                          self.state.project_cfg.get("ann_chunk_size"))}

                if inmain(user_cancelled):
                    map(lambda f: f.cancel(), futures.keys())
                    executor.shutdown(wait=False, cancel_futures=True)

                for future, chunk in futures.items():
                    if inmain(user_cancelled):
                        inmain(hide_wait_box)
                        executor.shutdown(wait=False, cancel_futures=True)

                    try:
                        res = CancelledError("Auto analysis cancelled") if future.cancelled() else future.result()

                        if isinstance(res, Exception):
                            logger.error("Fetching a chunk of auto analysis failed. Reason: %s", res)

                            self._analysis[Analysis.UNSUCCESSFUL] += len(chunk)

                            err_msg = f"Auto Analysis {'Cancelled' if isinstance(res, CancelledError) else 'Failed'}"

                            if isinstance(res, HTTPError):
                                err_msg = res.response.json().get("error", err_msg)

                            for function_id in chunk:
                                func_addr = next((func_addr for func_addr, func_id in self.analyzed_functions.items()
                                                  if function_id == func_id), None)

                                if func_addr:
                                    resultsData.append((next((function["name"] for function in self._functions
                                                              if func_addr == function["start_addr"]), "Unknown"),
                                                        "N/A", None, err_msg,))
                        else:
                            for symbol in res:
                                func_addr = next((func_addr for func_addr, func_id in self.analyzed_functions.items()
                                                  if symbol["origin_function_id"] == func_id), None)

                                if func_addr:
                                    self._analysis[Analysis.SUCCESSFUL.value] += 1

                                    symbol["function_addr"] = func_addr
                                    symbol["org_func_name"] = next((function["name"] for function in self._functions
                                                                    if func_addr == function["start_addr"]), "Unknown")

                                    logger.info("Found similar function '%s' with a confidence level of '%s",
                                                symbol["nearest_neighbor_function_name"], str(symbol["confidence"]))

                                    resultsData.append((symbol["org_func_name"],
                                                        f"{symbol['nearest_neighbor_function_name']} "
                                                        f"({symbol['nearest_neighbor_binary_name']})",
                                                        CheckableItem(symbol),
                                                        "Can be renamed with a confidence level of "
                                                        f"{float(str(symbol['confidence'])[:6]) * 100:#.02f}%",))
                    finally:
                        pos += len(chunk)
                        inmain(self.ui.progressBar.setProperty, "value", pos)

            resultsData.sort(key=lambda tup: tup[0])

            self._analysis[Analysis.TOTAL.value] = len(resultsData)

            inmain(inmain(self.ui.resultsTable.model).fill_table, resultsData)
        except HTTPError as e:
            logger.error("Fetching auto analysis failed. Reason: %s", e)

            Dialog.showError("Auto Analysis", f"Auto Analysis Error: {e.response.json()['error']}")
        except RequestException as e:
            logger.error("An unexpected error has occurred. %s", e)
        finally:
            inmain(hide_wait_box)
            inmain(self._tab_changed, 1)
            inmain(self.ui.tabWidget.setCurrentIndex, 1)
            inmain(self.ui.fetchButton.setEnabled, True)
            inmain(self.ui.confidenceSlider.setEnabled, True)
            inmain(self.ui.progressBar.setProperty, "value", 0)

            width: int = inmain(self.ui.resultsTable.width)

            inmain(self.ui.resultsTable.setColumnWidth, 0, width * .2)
            inmain(self.ui.resultsTable.setColumnWidth, 1, width * .4)
            inmain(self.ui.resultsTable.setColumnWidth, 2, width * .1)
            inmain(self.ui.resultsTable.setColumnWidth, 3, width * .3)

    def _filter(self, filter_text) -> None:
        if self.ui.tabWidget.currentIndex() == 0:
            self.typing_timer.start(self.searchDelay)     # Starts the countdown to call the filtering method
        else:
            table = self.ui.resultsTable

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

    def _search_collection(self, search: str = None) -> None:
        try:
            inmain(show_wait_box, "HIDECANCEL\nGetting RevEng.AI collections…")

            inmain(self.ui.fetchButton.setEnabled, False)

            res: Response = RE_collection_search(search)

            collections = []

            for collection in res.json()["collections"]:
                if isinstance(collection, str):
                    collections.append((collection,
                                        CheckableItem(checked=self.ui.layoutFilter.is_present(collection)),))
                else:
                    collections.append((IconItem(collection["name"],
                                                 "lock.png" if collection["scope"] == "PRIVATE" else
                                                 "unlock.png"),
                                        CheckableItem(checked=self.ui.layoutFilter.is_present(collection["name"])),))

            inmain(inmain(self.ui.collectionsTable.model).fill_table, collections)
            inmain(self.ui.collectionsTable.setColumnWidth, 0, inmain(self.ui.collectionsTable.width) * .9)
        except HTTPError as e:
            logger.error("Getting collections failed. Reason: %s", e)

            Dialog.showError("Auto Analysis", f"Auto Analysis Error: {e.response.json()['error']}")
        except RequestException as e:
            logger.error("An unexpected error has occurred. %s", e)
        finally:
            inmain(hide_wait_box)
            inmain(self._tab_changed, 0)
            inmain(self.ui.tabWidget.setCurrentIndex, 0)
            inmain(self.ui.fetchButton.setEnabled, True)
            inmain(self.ui.fetchButton.setFocus)

    def _rename_functions(self):
        batches = []

        for row_item in self.ui.resultsTable.model().get_datas():
            if isinstance(row_item[2], CheckableItem) and row_item[2].checkState == Qt.Checked:
                self._rename_function(row_item, batches)

        if len(batches):
            cnt = len(batches)

            # trunk the list of unrenamed functions
            del batches[5:]

            if len(batches) != cnt:
                batches.append("\n     • …")

            idc.warning(f"Can't rename the following{'' if cnt == 1 else ' ' + str(cnt)} function{'s'[:cnt ^ 1]}, "
                        f"name already exists for:{''.join(batches)}")

    def _rename_function(self, selected, batches: list = None) -> None:
        if selected and len(selected) > 3 and isinstance(selected[2], SimpleItem):
            symbol = selected[2].data

            if IDAUtils.set_name(symbol["function_addr"] + self.base_addr, symbol["nearest_neighbor_function_name"]):
                inthread(self._set_function_renamed, symbol["function_addr"], symbol["nearest_neighbor_function_name"])

                logger.info("Renowned %s in %s with confidence of '%s",
                            symbol["org_func_name"], symbol["nearest_neighbor_function_name"], symbol["confidence"])
            else:
                logger.warning("Symbol name %s already exists", symbol["nearest_neighbor_function_name"])

                if batches is not None:
                    batches.append(sub(r"^(.{10}).*\|(.{10}).*$", "\n     • \g<1>… ➡ \g<2>…",
                                       f"{symbol['org_func_name']}|{symbol['nearest_neighbor_function_name']}"))
                else:
                    idc.warning(f"Can't rename {symbol['org_func_name']}. Name {symbol['nearest_neighbor_function_name']} already exists.")

    def _selected_collections(self) -> list[str]:
        return [self.ui.layoutFilter.itemAt(idx).widget().objectName() for idx in range(self.ui.layoutFilter.count())]

    def _filter_collections(self):
        self._search_collection(self.ui.collectionsFilter.text().lower())

    def _state_change(self, index: QModelIndex):
        item = self.ui.collectionsTable.model().get_data(index.row())

        if item[1].checkState == Qt.Checked:
            self.ui.layoutFilter.add_card(item[0].text if isinstance(item[0], SimpleItem) else item[0])
        else:
            self.ui.layoutFilter.remove_card(item[0].text if isinstance(item[0], SimpleItem) else item[0])

    def _callback(self, text: str) -> None:
        for row_item in self.ui.collectionsTable.model().get_datas():
            if isinstance(row_item[1], CheckableItem) and \
                    (isinstance(row_item[0], str) and row_item[0] == text or
                     isinstance(row_item[0], SimpleItem) and row_item[0].text == text):
                row_item[1].checkState = Qt.Unchecked

        self.ui.collectionsTable.model().layoutChanged.emit()

    # Yield successive n-sized
    # chunks from l.
    @staticmethod
    def _divide_chunks(l: list, n: int = 50) -> list:
        # looping till length l
        for idx in range(0, len(l), n):
            yield l[idx:idx + n]
