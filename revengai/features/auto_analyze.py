import logging
from concurrent.futures import ThreadPoolExecutor, CancelledError
from enum import IntEnum
from re import sub

import idc
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QMenu
from idaapi import hide_wait_box, show_wait_box, user_cancelled
from idautils import Functions
from requests import HTTPError, RequestException
from reait.api import RE_nearest_symbols_batch
from reait.api import RE_collections_search
from reait.api import RE_binaries_search
from revengai.features import BaseDialog
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.misc.qtutils import inthread, inmain
from revengai.misc.utils import IDAUtils
from revengai.models import CheckableItem, IconItem, SimpleItem
from revengai.models.checkable_model import RevEngCheckableTableModel
from revengai.ui.auto_analysis_panel_2 import Ui_AutoAnalysisPanel
from datetime import datetime

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
        self.ui.searchButton.clicked.connect(self._filter_collections)
        self.ui.searchQuery.returnPressed.connect(self._filter_collections)
        self.ui.collectionsTable.horizontalHeader().setDefaultAlignment(
            Qt.AlignCenter
        )
        self.ui.collectionsTable.setModel(
            RevEngCheckableTableModel(
                data=[],
                columns=[0],
                parent=self,
                header=[
                    "",  # Include
                    "Name",
                    "Type",
                    "Date",
                    "Model Name",
                    "Owner",
                    "ID"
                ],
            )
        )

        self.ui.collectionsTable.model().dataChanged.connect(
            self._state_change
        )

        self.ui.resultsFilter.textChanged.connect(self._filter)
        self.ui.resultsTable.customContextMenuRequested.connect(
            self._table_menu)
        self.ui.resultsTable.horizontalHeader().setDefaultAlignment(
            Qt.AlignCenter
        )
        self.ui.resultsTable.setModel(
            RevEngCheckableTableModel(
                data=[],
                columns=[0],
                parent=self,
                header=[
                    "Successful",
                    "Original Function Name",
                    "Matched Function Name",
                    "Signature",
                    "Matched Binary",
                    "Confidence",
                    "Error",
                ],
            )
        )

        self.ui.fetchResultsButton.clicked.connect(self._start_analysis)
        self.ui.renameButton.clicked.connect(self._rename_functions)

        self.ui.confidenceSlider.valueChanged.connect(self._confidence)
        self.ui.tabWidget.tabBarClicked.connect(self._tab_changed)

        self._confidence(self.ui.confidenceSlider.sliderPosition())

        self._functions = []
        self._analysis = [0] * len(Analysis)

        for func_ea in Functions():
            start_addr = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
            if IDAUtils.is_in_valid_segment(start_addr):
                # add only if the function name starts with sub_
                name = IDAUtils.get_demangled_func_name(func_ea)
                if name.startswith("sub_"):
                    self._functions.append(
                        {
                            "name": name,
                            "start_addr": (start_addr - self.base_addr),
                            "end_addr": (
                                idc.get_func_attr(func_ea, idc.FUNCATTR_END)
                                - self.base_addr
                            ),
                        }
                    )

        self.ui.progressBar.setProperty(
            "maximum", 2 + (len(self._functions) << 1))

    def showEvent(self, event):
        super(AutoAnalysisDialog, self).showEvent(event)

        inthread(self._search_collection)

    def closeEvent(self, event):
        super(AutoAnalysisDialog, self).closeEvent(event)

        self._analysis.clear()
        self._functions.clear()

    def _table_menu(self) -> None:
        rows = sorted(
            set(index.row()
                for index in self.ui.resultsTable.selectedIndexes())
        )
        selected = self.ui.resultsTable.model().get_data(rows[0])

        if (
                selected
                and self.ui.renameButton.isEnabled()
                and isinstance(selected[2], CheckableItem)
        ):
            menu = QMenu()
            renameAction = menu.addAction(self.ui.renameButton.text())
            renameAction.triggered.connect(
                lambda: self._rename_function(selected))

            func_id = selected[2].data["nearest_neighbor_id"]
            breakdownAction = menu.addAction("View Function Breakdown")
            breakdownAction.triggered.connect(
                lambda: self._function_breakdown(func_id))

            # summariesAction = menu.addAction("Generate AI Summaries")
            # summariesAction.triggered.connect(
            # lambda: self._generate_summaries(func_id))

            menu.exec_(QCursor.pos())

    def _start_analysis(self) -> None:
        inthread(self._auto_analysis)

    def _auto_analysis(self) -> None:
        try:
            inmain(show_wait_box, "Getting results…")

            self._analysis = [
                0,
            ] * len(Analysis)

            inmain(self.ui.fetchResultsButton.setEnabled, False)
            inmain(self.ui.renameButton.setEnabled, False)
            inmain(self.ui.confidenceSlider.setEnabled, False)
            inmain(self.ui.progressBar.setProperty, "value", 1)

            inmain(inmain(self.ui.resultsTable.model).fill_table, [])
            inmain(self._tab_changed, inmain(self.ui.tabWidget.currentIndex))

            if not self.analyzed_functions or \
                    len(self.analyzed_functions) == 0:
                self._get_analyze_functions()

            resultsData = []
            function_ids = []
            nb_func = len(self._functions)
            self._analysis[Analysis.TOTAL.value] = nb_func

            for idx, func in enumerate(self._functions):
                idx += 1
                logger.info(
                    "Searching for %s [%d/%d]", func["name"], idx, nb_func)

                inmain(self.ui.progressBar.setProperty, "value", idx)

                function_id = self.analyzed_functions.get(
                    func["start_addr"], None)

                if function_id:
                    function_ids.append(function_id)
                else:
                    self._analysis[Analysis.SKIPPED.value] += 1
                    resultsData.append(
                        (
                            # Successful
                            CheckableItem(None, checked=False),
                            # Original Function Name
                            func["name"],
                            # Matched Function Names
                            "N/A",
                            # Signature
                            SimpleItem(text="N/A", data=None),
                            # Matched Binary
                            "N/A",
                            # Confidence
                            "0.0%",
                            # Error
                            "No Similar Function Found",
                        )
                    )

            pos = 1 + nb_func

            inmain(self.ui.progressBar.setProperty, "value", pos)

            max_workers = 1
            if self.state.project_cfg.get("parallelize_query") and not inmain(
                    user_cancelled
            ):
                max_workers = self.state.project_cfg.get("max_workers")

            # Launch parallel tasks
            with ThreadPoolExecutor(
                    max_workers=max_workers, thread_name_prefix="reai-batch"
            ) as executor:
                filter_data = inmain(self._selected_collections)
                distance = 1.0 - (
                    int(inmain(self.ui.confidenceSlider.property, "value"))
                    / int(inmain(
                        self.ui.confidenceSlider.property,
                        "maximum"
                    ))
                )

                def worker(chunk: list[int]) -> any:
                    try:
                        if inmain(user_cancelled):
                            raise CancelledError("Analyse binary cancelled")

                        res: dict = RE_nearest_symbols_batch(
                            function_ids=chunk,
                            distance=distance,
                            collections=filter_data["collections"],
                            binaries=filter_data["binaries"],
                            nns=1,
                            debug_enabled=inmain(self.ui.checkBox.isChecked)
                        ).json()

                        function_ids = ", ".join(map(str, chunk))

                        logger.info(
                            f"Completed batch for functions {function_ids}"
                        )

                        matches = res.get("function_matches", [])

                        if not matches:
                            logger.warning(
                                f"Batch for functions {function_ids} returned"
                                " no results"
                            )

                            return []

                        logger.info(
                            f"Batch for functions {function_ids} returned "
                            f"{len(matches)} results"
                        )

                        return matches

                    except HTTPError as e:
                        logger.error(
                            "Fetching a chunk of auto analysis failed."
                            " Reason: %s",
                            e,
                        )
                        return None

                # Start the ANN batch operations and mark each future with its
                # chunk
                futures = {
                    executor.submit(worker, chunk): chunk
                    for chunk in AutoAnalysisDialog._divide_chunks(
                        function_ids, self.state.project_cfg.get("chunk_size")
                    )
                }

                if inmain(user_cancelled):
                    map(lambda f: f.cancel(), futures.keys())
                    executor.shutdown(wait=False, cancel_futures=True)

                for future, chunk in futures.items():
                    if inmain(user_cancelled):
                        inmain(hide_wait_box)
                        executor.shutdown(wait=False, cancel_futures=True)

                    try:
                        res = (
                            CancelledError("Analyse binary cancelled")
                            if future.cancelled()
                            else future.result()
                        )

                        if isinstance(res, Exception):
                            logger.error(
                                "Fetching a chunk of Analyse Binary failed."
                                " Reason: %s",
                                res,
                            )

                            self._analysis[Analysis.UNSUCCESSFUL] += len(chunk)

                            if isinstance(res, CancelledError):
                                err_msg = "Analyse Binary Cancelled"
                            else:
                                err_msg = "Analyse Binary Failed"

                            if isinstance(res, HTTPError):
                                err_msg = res.response.json().get(
                                    "error",
                                    err_msg
                                )

                            for function_id in chunk:
                                func_addr = next(
                                    (
                                        func_addr
                                        for func_addr, func_id in
                                        self.analyzed_functions.items()
                                        if function_id == func_id
                                    ),
                                    None,
                                )

                                # header=[
                                #     "Successful",
                                #     "Original Function Name",
                                #     "Matched Function Name",
                                #     "Signature",
                                #     "Matched Binary",
                                #     "Confidence",
                                #     "Error",
                                # ],

                                if func_addr:
                                    resultsData.append(
                                        (
                                            # Successful
                                            CheckableItem(None, checked=False),
                                            # Original Function Name
                                            next(
                                                (
                                                    function["name"]
                                                    for function in
                                                    self._functions
                                                    if func_addr == function["start_addr"]
                                                ),
                                                "Unknown",
                                            ),
                                            # Matched Function Names
                                            "N/A",
                                            # Signature
                                            SimpleItem(text="N/A", data=None),
                                            # Matched Binary
                                            SimpleItem(text="N/A", data=None),
                                            # Confidence
                                            "0.0%",
                                            # Error
                                            err_msg,
                                        )
                                    )
                        else:
                            for symbol in res:
                                func_addr = next(
                                    (
                                        func_addr
                                        for func_addr, func_id in
                                        self.analyzed_functions.items()
                                        if symbol["origin_function_id"] ==
                                        func_id
                                    ),
                                    None,
                                )

                                func_name = next(
                                    (
                                        function["name"]
                                        for function in self._functions
                                        if func_addr == function["start_addr"]
                                    ),
                                    "Unknown",
                                )

                                if "FUN_" not in func_name:
                                    if func_addr:
                                        symbol["org_func_name"] = next(
                                            (
                                                function["name"]
                                                for function in self._functions
                                                if func_addr ==
                                                function["start_addr"]
                                            ),
                                            "Unknown",
                                        )

                                        nnfn = symbol["nearest_neighbor_function_name"]
                                        nnbn = symbol["nearest_neighbor_binary_name"]

                                        if (nnfn == symbol["org_func_name"]):
                                            self._analysis[Analysis.SKIPPED.value] += 1
                                            resultsData.append((
                                                # Successful
                                                CheckableItem(
                                                    None,
                                                    checked=False
                                                ),
                                                # Original Function Name
                                                symbol["org_func_name"],
                                                # Matched Function Names
                                                nnfn,
                                                # Signature
                                                SimpleItem(
                                                    text="N/A",
                                                    data=None
                                                ),
                                                # Matched Binary
                                                nnbn,
                                                # Confidence
                                                "0.0%",
                                                # Error
                                                "Same Function Name Found",
                                            ))
                                        else:
                                            self._analysis[
                                                Analysis.SUCCESSFUL.value
                                            ] += 1

                                            confidence = symbol["confidence"] * 100

                                            logger.info(
                                                f"Found similar function "
                                                f"'{nnfn}' with a confidence"
                                                " level of "
                                                f"'{confidence:#.02f}'"
                                            )

                                            symbol["function_addr"] = func_addr

                                            resultsData.append(
                                                (
                                                    # Successful
                                                    CheckableItem(symbol),
                                                    # Original Function Name
                                                    symbol["org_func_name"],
                                                    # Matched Function Names
                                                    nnfn,
                                                    # Signature
                                                    SimpleItem(
                                                        text="N/A",
                                                        data=None
                                                    ),
                                                    # Matched Binary
                                                    nnbn,
                                                    # Confidence
                                                    f"{confidence:#.02f}%",
                                                    # Error
                                                    "",
                                                )
                                            )
                    finally:
                        pos += len(chunk)
                        inmain(self.ui.progressBar.setProperty, "value", pos)

            resultsData.sort(key=lambda tup: tup[1])

            # This is dumb we already populated it with the number of functions
            # self._analysis[Analysis.TOTAL.value] = len(resultsData)

            inmain(inmain(self.ui.resultsTable.model).fill_table, resultsData)
        except HTTPError as e:
            logger.error("Fetching analyse binary failed. Reason: %s", e)

            Dialog.showError(
                "Analyse Binary",
                f"Analyse Binary Error: {e.response.json()['error']}"
            )
        except RequestException as e:
            logger.error("An unexpected error has occurred. %s", e)
        finally:
            inmain(hide_wait_box)
            inmain(self._tab_changed, 1)
            inmain(self.ui.tabWidget.setCurrentIndex, 1)
            inmain(self.ui.fetchResultsButton.setEnabled, True)
            inmain(self.ui.confidenceSlider.setEnabled, True)
            inmain(self.ui.progressBar.setProperty, "value", 0)

            width: int = inmain(self.ui.resultsTable.width)

            # Successful
            inmain(self.ui.resultsTable.setColumnWidth, 0, round(width * 0.08))
            # Original Function Name
            inmain(self.ui.resultsTable.setColumnWidth, 1, round(width * 0.2))
            # Matched Function Name
            inmain(self.ui.resultsTable.setColumnWidth, 2, round(width * 0.2))
            # Signature
            inmain(self.ui.resultsTable.setColumnWidth, 3, round(width * 0.1))
            # Matched Binary
            inmain(self.ui.resultsTable.setColumnWidth, 4, round(width * 0.2))
            # Confidence
            inmain(self.ui.resultsTable.setColumnWidth, 5, round(width * 0.08))
            # Error
            inmain(self.ui.resultsTable.setColumnWidth, 6, round(width * 0.3))

    def _filter(self, filter_text) -> None:
        table = self.ui.resultsTable

        for row in range(table.model().rowCount()):
            item = table.model().index(row, 0)
            table.setRowHidden(
                row,
                filter_text.lower() not in
                item.sibling(row, 0).data().lower()
            )

    def _confidence(self, value: int) -> None:
        if self.ui.tabWidget.currentIndex() == 0:
            self.ui.description.setText(f"Confidence: {value:#02d}")

    def _tab_changed(self, index: int) -> None:
        if index == 0:
            self.ui.description.setVisible(True)
            self.ui.renameButton.setEnabled(False)
            self.ui.fetchDataTypesButton.setEnabled(False)
            self.ui.description.setText(
                f"Confidence: {self.ui.confidenceSlider.sliderPosition():#02d}"
            )
        else:
            self.ui.description.setVisible(
                self._analysis[Analysis.TOTAL.value] > 0)
            self.ui.renameButton.setEnabled(
                self._analysis[Analysis.SUCCESSFUL.value] > 0
            )
            self.ui.fetchDataTypesButton.setEnabled(
                self._analysis[Analysis.SUCCESSFUL.value] > 0
            )
            self.ui.description.setText(
                "Total Functions Analysed: "
                f"{self._analysis[Analysis.TOTAL.value]}<br/>"
                "Successful Analyses: "
                f"{self._analysis[Analysis.SUCCESSFUL.value]}<br/>"
                "Skipped Analyses: "
                f"{self._analysis[Analysis.SKIPPED.value]}<br/>"
                "Errored Analyses: "
                f"{self._analysis[Analysis.UNSUCCESSFUL.value]}"
            )

    def _search_collection(self, query: dict = {}) -> None:

        def parse_date(date: str) -> str:
            parsed_date = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%f")
            return f"{parsed_date:%Y-%m-%d %H:%M:%S}"

        try:
            inmain(show_wait_box, "HIDECANCEL\nGetting RevEng.AI collections…")

            inmain(self.ui.fetchResultsButton.setEnabled, False)

            logger.info(
                "Searching for collections with '%s'", query or "N/A"
            )

            res: dict = RE_collections_search(
                query=query,
                page=1,
                page_size=1024,
            ).json()

            result_collections = res.get("data", {}).get("results", [])

            logger.info(f"Found {len(result_collections)} collections")

            collections = []

            for collection in result_collections:
                data = {
                    "item_name": collection["collection_name"],
                    "item_id": collection["collection_id"],
                }

                collections.append(
                    (
                        CheckableItem(
                            checked=self.ui.layoutFilter.is_present(
                                data
                            )
                        ),
                        IconItem(
                            collection["collection_name"],
                            (
                                "lock.png"
                                if collection["scope"] == "PRIVATE"
                                else "unlock.png"
                            ),
                        ),
                        "Collection",
                        parse_date(collection["last_updated_at"]),
                        collection["model_name"],
                        collection["owned_by"],
                        collection["collection_id"]
                    )
                )

            # include binaries too
            res: dict = RE_binaries_search(
                query=query,
                page=1,
                page_size=1024,
            ).json()

            result_binaries = res.get("data", {}).get("results", [])

            logger.info(f"Found {len(result_binaries)} binaries")

            for binary in result_binaries:
                data = {
                    "item_name": binary["binary_name"],
                    "item_id": binary["binary_id"],
                }
                collections.append(
                    (
                        CheckableItem(
                            checked=self.ui.layoutFilter.is_present(
                                data
                            )
                        ),
                        IconItem(
                            binary["binary_name"],
                            "file.png",
                        ),
                        "Binary",
                        parse_date(binary["created_at"]),
                        binary["model_name"],
                        binary["owned_by"],
                        binary["binary_id"]
                    )
                )

            inmain(
                inmain(self.ui.collectionsTable.model).fill_table,
                collections
            )

            inmain(
                self.ui.collectionsTable.setColumnWidth,
                0,
                round(inmain(self.ui.collectionsTable.width) * 0.1),
            )
        except HTTPError as e:
            if e.response.status_code != 400:
                message = e.json().get("error", "Unknown error")
                logger.error(f"Getting collections failed. Reason: {message}")
                Dialog.showError(
                    "Auto Analysis",
                    f"Auto Analysis Error: {message}"
                )
        except RequestException as e:
            logger.error("An unexpected error has occurred. %s", e)
        finally:
            inmain(hide_wait_box)
            inmain(self._tab_changed, 0)
            inmain(self.ui.tabWidget.setCurrentIndex, 0)
            inmain(self.ui.fetchResultsButton.setEnabled, True)
            inmain(self.ui.fetchResultsButton.setFocus)

    def _rename_functions(self):
        batches = []
        functions = {}

        for row_item in self.ui.resultsTable.model().get_datas():
            if (
                    isinstance(row_item[0], CheckableItem)
                    and row_item[0].checkState == Qt.Checked
            ):
                symbol = row_item[0].data

                nnfn = symbol['nearest_neighbor_function_name']

                if IDAUtils.set_name(
                        symbol["function_addr"] + self.base_addr,
                        symbol["nearest_neighbor_function_name"],
                ):
                    func_id = self._get_function_id(symbol["function_addr"])
                    if func_id:
                        functions[func_id] = nnfn
                        continue

                batches.append(
                    "\n     • "
                    + sub(
                        r"^(.{10}).*\s+➡\s+(.{10}).*$",
                        r"\g<1>…  ➡  \g<2>…",
                        f"{symbol['org_func_name']}  ➡  {nnfn}",
                    )
                )

        if len(functions):
            inthread(self._batch_function_rename, functions)

        if len(batches):
            cnt = len(batches)

            # trunk the list of unrenamed functions
            del batches[5:]

            if len(batches) != cnt:
                batches.append("\n     • …")

            idc.warning(
                "Can't rename the following"
                f"{'' if cnt == 1 else ' ' + str(cnt)} function{'s'[:cnt ^ 1]}"
                f", name already exists for: {''.join(batches)}"
            )

    def _rename_function(self, selected, batches: list = None) -> None:
        if selected and len(selected) > 3 and isinstance(
                selected[2],
                SimpleItem
        ):
            symbol = selected[2].data

            function_addr = symbol["function_addr"] + self.base_addr
            original_name = symbol["org_func_name"]
            original_id = symbol["origin_function_id"]
            matched_name = symbol["nearest_neighbor_function_name"]
            confidence = symbol["confidence"]
            nnfid = symbol["nearest_neighbor_id"]
            nnbid = symbol["nearest_neighbor_binary_id"]
            nn_is_debug = symbol["nearest_neighbor_debug"]

            if IDAUtils.set_name(
                    function_addr,
                    matched_name,
            ):
                # perform the renaming on our platform too
                inthread(
                    self._function_rename,
                    function_addr,
                    matched_name,
                    original_id,
                )

                # if nn_is_debug:
                #     # import datatypes from the nearest neighbor binary
                #     inthread(
                #         self._function_import_symbol_datatypes,
                #         nnbid,
                #         nnfid,
                #         function_addr,
                #     )

                logger.info(
                    "Renowned %s in %s with confidence of '%s",
                    original_name,
                    matched_name,
                    confidence,
                )
            else:
                logger.warning(
                    "Unable to rename %s in %s. Name %s already exists.",
                    original_name,
                    matched_name,
                    matched_name,
                )

                idc.warning(
                    f"Can't rename {original_name}. Name {matched_name} "
                    "already exists."
                )

    def _selected_collections(self) -> dict:
        collections = []
        binaries = []
        for idx in range(self.ui.layoutFilter.count()):
            item = self.ui.layoutFilter.itemAt(idx).widget()
            data = item.custom_data
            if data["is_collection"]:
                collections.append(data["item_id"])
            else:
                binaries.append(data["item_id"])
        return {
            "collections": collections,
            "binaries": binaries,
        }

    def _filter_collections(self):
        query = self.ui.searchQuery.text().lower()
        try:
            query_data = self._parse_search_query(query)
            self._search_collection(query_data)
        except ValueError as e:
            logger.error("Invalid search query: %s", query)
            Dialog.showError(
                "Auto Analysis",
                f"Invalid search query: {e}"
            )

    def _state_change(self, index: QModelIndex):
        row = index.row()
        item = self.ui.collectionsTable.model().get_data(row)

        item_name = item[1].text if isinstance(
            item[1], SimpleItem) else item[1]

        item_id = item[6]
        is_collection = item[2] == "Collection"

        data = {
            "row": row,
            "is_collection": is_collection,
            "item_name": item_name,
            "item_id": item_id,
        }

        if item[0].checkState == Qt.Checked:
            self.ui.layoutFilter.add_card(
                data
            )
        else:
            self.ui.layoutFilter.remove_card(
                data
            )

    def _callback(self, data: dict) -> None:
        row_element = self.ui.collectionsTable.model().get_data(data["row"])
        if row_element[6] == data["item_id"]:
            row_element[0].checkState = Qt.Unchecked
            self.ui.collectionsTable.model().layoutChanged.emit()

    # Yield successive n-sized
    # chunks from data.
    @staticmethod
    def _divide_chunks(data: list, n: int = 50) -> list:
        # looping till length l
        for idx in range(0, len(data), n):
            yield data[idx: idx + n]
