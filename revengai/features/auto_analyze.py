import logging
from concurrent.futures import ThreadPoolExecutor, CancelledError
from enum import IntEnum

import idc
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QMenu
from PyQt5.QtGui import QIcon
from idaapi import hide_wait_box, show_wait_box, user_cancelled
from idautils import Functions
from requests import HTTPError, RequestException
from reait.api import RE_nearest_symbols_batch
from reait.api import RE_collections_search
from reait.api import RE_binaries_search
from reait.api import RE_name_score
from revengai.features import BaseDialog
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.misc.qtutils import inthread, inmain
from revengai.misc.utils import IDAUtils
from revengai.models import CheckableItem, IconItem, SimpleItem
from revengai.models.checkable_model import RevEngCheckableTableModel
from revengai.models.table_model import RevEngTableModel
from revengai.ui.auto_analysis_panel import Ui_AutoAnalysisPanel
from datetime import datetime
from revengai.misc.datatypes import (
    apply_multiple_data_types,
    apply_data_types,
    fetch_data_types,
    wait_box_decorator,
    apply_signature,
)
from typing import Generator
from libbs.artifacts import _art_from_dict
from libbs.artifacts import (
    Function,
)
from libbs.api import DecompilerInterface

import idaapi

from PyQt5.QtCore import QTimer

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
        self.ui.searchQuery.returnPressed.connect(
            self._filter_collections
        )
        self.ui.fetchDataTypesButton.clicked.connect(
            self._fetch_data_types
        )
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
            RevEngTableModel(
                data=[],
                # columns=[0],
                parent=self,
                header=[
                    "Successful",
                    "Original Function Name",
                    "Matched Function Name",
                    "Signature",
                    "Matched Binary",
                    "Similarity",
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
            # why should we care if the function is in a valid segment?
            # as long as IDA identifies it as a function, we MUST analyze it
            if IDAUtils.is_in_exec_segment(start_addr):
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

        self._fetch_timer = None
        self._fetch_executor = None
        self._fetch_future = None

        self._apply_types_timer = None
        self._apply_types_executor = None
        self._apply_types_future = None

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
                and isinstance(selected[0], IconItem)
                and selected[0].data is not None
        ):
            menu = QMenu()
            renameAction = menu.addAction("Rename Function")
            renameAction.triggered.connect(
                lambda: self._rename_function(selected))

            func_id = selected[0].data["nearest_neighbor_id"]
            breakdownAction = menu.addAction("View Function Breakdown")
            breakdownAction.triggered.connect(
                lambda: self._function_breakdown(func_id))

            func_addr = selected[0].data["function_addr"] + self.base_addr
            matched_func_id = selected[0].data["nearest_neighbor_id"]
            fetchDataTypesAction = menu.addAction("Fetch Data Types")
            fetchDataTypesAction.triggered.connect(
                lambda: self._function_get_datatypes(
                    # row
                    rows[0],
                    # matched function id
                    matched_func_id,
                )
            )

            if selected[3].data is not None:
                applyDataTypesAction = menu.addAction("Apply Data Types")
                applyDataTypesAction.triggered.connect(
                    lambda: self._function_import_symbol_datatypes(
                        # signature
                        selected[3].data,
                        # function address
                        func_addr,
                    )
                )

            excludeRowAction = menu.addAction("Exclude")
            excludeRowAction.triggered.connect(
                lambda: self._exclude_row(rows[0])
            )

            includeRowAction = menu.addAction("Include")
            includeRowAction.triggered.connect(
                lambda: self._include_row(rows[0])
            )

            menu.exec_(QCursor.pos())

    def _exclude_row(self, row) -> None:
        model = self.ui.resultsTable.model()
        index = model.index(row, 0)
        item: IconItem = model.getModelData(index)
        item.icon = QIcon(
            IconItem._plugin_resource("exclude.png")
        )
        item.text = "Excluded"
        model.dataChanged.emit(index, index)

    def _include_row(self, row) -> None:
        model = self.ui.resultsTable.model()
        index = model.index(row, 0)
        item: IconItem = model.getModelData(index)
        item.icon = QIcon(
            IconItem._plugin_resource("success.png")
        )
        item.text = "Yes"
        model.dataChanged.emit(index, index)

    def _fetch_data_types(self, *args) -> None:
        """Non-blocking version using ThreadPoolExecutor"""
        try:
            # get the model from the result table
            data = self.ui.resultsTable.model().get_datas()
            function_ids = []

            for element in data:
                icon_item = element[0]
                is_succeed = icon_item.text == "Yes"
                if is_succeed:
                    function_id = icon_item.data.get(
                        "nearest_neighbor_id", None)
                    if function_id:
                        function_ids.append(function_id)

            if not function_ids:
                logger.info("No functions selected for data type fetching.")
                return

            # Show progress and disable UI
            show_wait_box("HIDECANCEL\nGetting data types…")
            self.ui.progressBar.show()
            self.ui.progressBar.setProperty("maximum", 100)
            self.ui.progressBar.setProperty("value", 0)
            self.ui.fetchDataTypesButton.setEnabled(False)

            # Create executor and submit task
            self._fetch_executor = ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="fetch-datatypes")

            def fetch_task():
                """The actual fetch operation running in background thread"""
                return fetch_data_types(
                    function_ids=function_ids,
                    progress_cb=self._fetch_progress_callback,
                    # We'll handle completion in the main thread
                    complete_cb=None,
                )

            # Submit the task
            self._fetch_future = self._fetch_executor.submit(fetch_task)

            # Start timer to check completion
            self._fetch_timer = QTimer()
            self._fetch_timer.timeout.connect(self._check_fetch_completion)
            self._fetch_timer.start(100)  # Check every 100ms

        except Exception as e:
            logger.error(f"Error starting fetch_data_types: {e}")
            self._cleanup_fetch_operation()

    def _fetch_progress_callback(self, progress: int) -> None:
        """
        Progress callback that runs on background thread but updates UI safely
        """
        inmain(self.ui.progressBar.setProperty, "value", progress)
        if progress >= 100:
            inmain(self.ui.progressBar.hide)

    def _check_fetch_completion(self) -> None:
        """Timer callback to check if fetch operation is complete"""
        if not self._fetch_future:
            self._cleanup_fetch_operation()
            return

        if user_cancelled():
            self._cancel_fetch_operation()
            return

        if self._fetch_future.done():
            try:
                completed_items = self._fetch_future.result()
                self._process_fetch_results(completed_items)
            except Exception as e:
                logger.error(f"Error in fetch_data_types: {e}")
                if isinstance(e, HTTPError):
                    resp = e.response.json()
                    error = resp.get("message", "Unexpected error occurred.")
                    logger.error(f"Error while fetching data types: {error}")
            finally:
                self._cleanup_fetch_operation()

    def _check_apply_types_completion(self) -> None:
        """Timer callback to check if apply_data_types operation is complete"""
        if not self._apply_types_future:
            self._cleanup_apply_types_operation()
            return

        if user_cancelled():
            self._cancel_apply_types_operation()
            return

        if self._apply_types_future.done():
            try:
                success = self._apply_types_future.result()
                if success is not None:
                    logger.error("Data types application failed: %s", success)
                else:
                    logger.info(
                        "Data types application completed successfully."
                    )
            except Exception as e:
                logger.error(f"Error in apply_data_types: {e}")
                if isinstance(e, HTTPError):
                    resp = e.response.json()
                    error = resp.get("message", "Unexpected error occurred.")
                    logger.error(f"Error while applying data types: {error}")
            finally:
                self._cleanup_apply_types_operation()

    def _cancel_apply_types_operation(self) -> None:
        """Cancel the ongoing apply operation"""
        if self._apply_types_future:
            self._apply_types_future.cancel()
        logger.info("Apply data types operation cancelled")
        self._cleanup_apply_types_operation()

    def _cleanup_apply_types_operation(self) -> None:
        """Clean up apply operation resources"""
        if self._apply_types_timer:
            self._apply_types_timer.stop()
            self._apply_types_timer = None

        if self._apply_types_executor:
            self._apply_types_executor.shutdown(wait=False)
            self._apply_types_executor = None

        self._apply_types_future = None

        # Re-enable UI and hide progress
        hide_wait_box()
        self.ui.progressBar.hide()
        self.ui.renameButton.setEnabled(True)

    def _process_fetch_results(self, completed_items: list) -> None:
        """Process the results from fetch_data_types"""
        if len(completed_items) == 0:
            logger.info("No data types found for the specified functions.")
            return

        logger.info(
            f"Applying signatures for {len(completed_items)} functions")

        model = self.ui.resultsTable.model()
        data = model.get_datas()

        for row in range(len(data)):
            row_data = data[row]
            icon_item = row_data[0]

            # skip failed items
            if icon_item.data is None:
                continue

            function_id = icon_item.data.get("nearest_neighbor_id", 0)
            logger.info(f"Applying signature for fid: {function_id}")

            match_data_types = next(
                (item for item in completed_items if item.get(
                    "function_id", 0) == function_id),
                None
            )

            if match_data_types is None:
                continue

            logger.info(f"Found matching data types for fid: {function_id}")

            func_types = match_data_types.get("func_types", None)
            func_deps = match_data_types.get("func_deps", [])

            if func_types is not None:
                from libbs.artifacts import _art_from_dict, Function
                fnc: Function = _art_from_dict(func_types)
                if fnc.name is None:
                    logger.warning(
                        f"Function {function_id} has no name, "
                        "skipping signature application."
                    )
                    continue
                logger.info(f"Applying signature for {fnc.name}")
                apply_signature(row, fnc, func_deps, self.ui.resultsTable)
            else:
                logger.error(
                    "Failed to get function data types "
                    f"for functionId {function_id}."
                )

    def _cancel_fetch_operation(self) -> None:
        """Cancel the ongoing fetch operation"""
        if self._fetch_future:
            self._fetch_future.cancel()
        logger.info("Fetch data types operation cancelled")
        self._cleanup_fetch_operation()

    def _cleanup_fetch_operation(self) -> None:
        """Clean up fetch operation resources"""
        if self._fetch_timer:
            self._fetch_timer.stop()
            self._fetch_timer = None

        if self._fetch_executor:
            self._fetch_executor.shutdown(wait=False)
            self._fetch_executor = None

        self._fetch_future = None

        # Re-enable UI and hide progress
        hide_wait_box()
        self.ui.progressBar.hide()
        self.ui.fetchDataTypesButton.setEnabled(True)

    @wait_box_decorator(
        "HIDECANCEL\nGetting data types for function…"
    )
    def _function_get_datatypes(
            self,
            row: int,
            matched_func_id: int = 0,
    ) -> None:
        try:

            completed_items = fetch_data_types(
                function_ids=[matched_func_id],
            )

            if len(completed_items) == 0:
                logger.info(
                    "No data types found for the specified function."
                )
                return

            logger.info(
                "Data types generation completed."
            )

            data_types = completed_items[0]

            func_types = data_types.get("func_types", None)
            func_deps = data_types.get("func_deps", None)

            fnc: Function = _art_from_dict(func_types)

            apply_signature(row, fnc, func_deps, self.ui.resultsTable)

        except HTTPError as e:
            errors = e.response.json().get(
                "errors",
                [{
                    "message": f"An unexpected error occurred. Sorry for the "
                    f"inconvenience. {e.response.status_code}"
                }],
            )

            logger.error(
                "Error while importing data types for the specified function:"
                f"{errors[0]['message']}"
            )

            inmain(idaapi.warning, errors[0]["message"])

    @wait_box_decorator(
        "HIDECANCEL\nApplying data types to function…"
    )
    def _function_import_symbol_datatypes(
        self,
        signature=None,
        function_addr: int = 0,
    ) -> None:
        deci = DecompilerInterface.discover(force_decompiler="ida")
        apply_data_types(
            function_addr,
            signature,
            deci=deci,
        )

    def _start_analysis(self) -> None:
        logger.info("Starting auto analysis…")
        inthread(self._auto_analysis)

    def _auto_analysis(self) -> None:
        logger.info("Auto analysis started")
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

            logger.info(
                "Found %d functions to analyze",
                len(self._functions)
            )

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
                            # CheckableItem(None, checked=False),
                            IconItem(
                                text="No",
                                resource_name="failed.png",
                                data=None
                            ),
                            # Original Function Name
                            func["name"],
                            # Matched Function Names
                            "N/A",
                            # Signature
                            SimpleItem(text="N/A", data=None),
                            # Matched Binary
                            "N/A",
                            # Similarity
                            "0.0%",
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

                        functions = []
                        for match in matches:
                            functions.append({
                                "function_id": match["origin_function_id"],
                                "function_name": match[
                                    "nearest_neighbor_function_name"
                                ],
                            })

                        response = RE_name_score(functions).json()["data"]
                        for function in response:
                            for match in matches:
                                if match["origin_function_id"] == function[
                                    "function_id"
                                ]:
                                    match["real_confidence"] = function[
                                        "box_plot"
                                    ]["average"]
                                    if match["real_confidence"] < (
                                            100 - (distance * 100)
                                    ):
                                        matches.remove(match)
                                        break

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
                                            IconItem(
                                                text="No",
                                                resource_name="failed.png",
                                                data=None
                                            ),
                                            # Original Function Name
                                            next(
                                                (
                                                    function["name"]
                                                    for function in
                                                    self._functions
                                                    if func_addr ==
                                                    function["start_addr"]
                                                ),
                                                "Unknown",
                                            ),
                                            # Matched Function Names
                                            "N/A",
                                            # Signature
                                            SimpleItem(text="N/A", data=None),
                                            # Matched Binary
                                            SimpleItem(text="N/A", data=None),
                                            # Similarity
                                            "0.0%",
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

                                        nnfn = symbol[
                                            "nearest_neighbor_function_name"
                                        ]
                                        nnbn = symbol[
                                            "nearest_neighbor_binary_name"
                                        ]

                                        if (nnfn == symbol["org_func_name"]):
                                            self._analysis[
                                                Analysis.SKIPPED.value
                                            ] += 1
                                            resultsData.append((
                                                # Successful
                                                # CheckableItem(
                                                #     None,
                                                #     checked=False
                                                # ),
                                                IconItem(
                                                    text="No",
                                                    resource_name="failed.png",
                                                    data=None
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
                                                # Similarity
                                                "0.0%",
                                                # Confidence
                                                "0.0%",
                                                # Error
                                                "Same Function Name Found",
                                            ))
                                        else:
                                            self._analysis[
                                                Analysis.SUCCESSFUL.value
                                            ] += 1

                                            similarity = symbol[
                                                "confidence"
                                            ] * 100
                                            confidence = symbol[
                                                "real_confidence"
                                            ]

                                            logger.info(
                                                f"Found similar function "
                                                f"'{nnfn}' with a confidence"
                                                " level of "
                                                f"'{confidence:#.02f}'"
                                            )

                                            symbol["function_addr"] = func_addr
                                            success = "success.png"

                                            resultsData.append(
                                                (
                                                    # Successful
                                                    # CheckableItem(symbol),
                                                    IconItem(
                                                        text="Yes",
                                                        resource_name=success,
                                                        data=symbol
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
                                                    # Similarity
                                                    f"{similarity:#.02f}%",
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
        except Exception as e:
            logger.error("An unexpected error has occurred. %s", e)
            Dialog.showError(
                "Auto Analysis",
                f"Unexpected error: {e}"
            )
            inmain(idaapi.warning, f"Unexpected error: {e}")
        finally:
            inmain(hide_wait_box)
            inmain(self.ui.fetchResultsButton.setEnabled, True)
            inmain(self.ui.progressBar.setProperty, "value", 0)
            inmain(self.ui.confidenceSlider.setEnabled, True)
            if len(resultsData) > 0:
                inmain(self._tab_changed, 1)
                inmain(self.ui.tabWidget.setCurrentIndex, 1)
                width: int = inmain(self.ui.resultsTable.width)
                # Successful
                inmain(self.ui.resultsTable.setColumnWidth,
                       0, round(width * 0.08))
                # Original Function Name
                inmain(self.ui.resultsTable.setColumnWidth,
                       1, round(width * 0.2))
                # Matched Function Name
                inmain(self.ui.resultsTable.setColumnWidth,
                       2, round(width * 0.2))
                # Signature
                inmain(self.ui.resultsTable.setColumnWidth,
                       3, round(width * 0.1))
                # Matched Binary
                inmain(self.ui.resultsTable.setColumnWidth,
                       4, round(width * 0.2))
                # Similarity
                inmain(self.ui.resultsTable.setColumnWidth,
                       5, round(width * 0.08))
                # Confidence
                inmain(self.ui.resultsTable.setColumnWidth,
                       6, round(width * 0.08))
                # Error
                inmain(self.ui.resultsTable.setColumnWidth,
                       7, round(width * 0.3))

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
            self.ui.confidenceSlider.show()
            self.ui.description.setText(
                f"Confidence: {self.ui.confidenceSlider.sliderPosition():#02d}"
            )
            self.ui.progressBar.show()
        else:
            self.ui.progressBar.hide()
            self.ui.confidenceSlider.hide()
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

            try:
                res: dict = RE_collections_search(
                    query=query,
                    page=1,
                    page_size=1024,
                ).json()

                result_collections = res.get("data", {}).get("results", [])
            except HTTPError as e:
                resp = e.response.json()
                errors = resp.get("errors", [{}])
                error_code = errors[0].get("code", "unknown")
                if error_code == "missing":
                    result_collections = []
                else:
                    raise e

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
            try:
                res: dict = RE_binaries_search(
                    query=query,
                    page=1,
                    page_size=1024,
                ).json()
                result_binaries = res.get("data", {}).get("results", [])
            except HTTPError as e:
                resp = e.response.json()
                errors = resp.get("errors", [{}])
                error_code = errors[0].get("code", "unknown")
                if error_code == "missing":
                    result_binaries = []
                else:
                    raise e

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
            resp = e.response.json()
            message = resp.get(
                "error",
                "An unexpected error occurred. Sorry for the inconvenience.",
            )
            logger.error(
                f"Getting collections failed. Reason: {message}"
            )
        except RequestException as e:
            logger.error("An unexpected error has occurred. %s", e)
        finally:
            inmain(hide_wait_box)
            inmain(self._tab_changed, 0)
            inmain(self.ui.tabWidget.setCurrentIndex, 0)
            inmain(self.ui.fetchResultsButton.setEnabled, True)
            # inmain(self.ui.fetchResultsButton.setFocus)

    @wait_box_decorator(
        "HIDECANCEL\nRenaming functions and applying types…"
    )
    def _rename_functions(self, *args):
        data = self.ui.resultsTable.model().get_datas()

        to_process = []

        # TODO: possibly add a progress bar here
        for row in range(len(data)):
            if (
                    isinstance(data[row][0], IconItem)
                    and data[row][0].text == "Yes"
            ):
                symbol = data[row][0].data
                signature = data[row][3].data

                nnfn = symbol['nearest_neighbor_function_name_mangled']
                original_addr = symbol['function_addr'] + self.base_addr

                to_process.append({
                    "row": row,
                    "nnfn": nnfn,
                    "original_addr": original_addr,
                    "signature": signature,
                })

        # Show progress and disable UI
        show_wait_box("HIDECANCEL\nGetting data types…")
        self.ui.progressBar.show()
        self.ui.progressBar.setProperty("maximum", 100)
        self.ui.progressBar.setProperty("value", 0)
        self.ui.renameButton.setEnabled(False)

        # Create executor and submit task
        self._apply_types_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="fetch-datatypes")

        deci = DecompilerInterface.discover(force_decompiler="ida")

        def apply_task() -> None:
            """Apply the function rename and data types"""
            return apply_multiple_data_types(
                to_process,
                deci=deci,
                progress_cb=self._fetch_progress_callback,
                # We will handle completion in the main thread
                complete_cb=None
            )

        # Submit the task
        self._apply_types_future = self._apply_types_executor.submit(
            apply_task
        )

        # Start timer to check completion
        self._apply_types_timer = QTimer()
        self._apply_types_timer.timeout.connect(
            self._check_apply_types_completion
        )
        self._apply_types_timer.start(100)  # Check every 100ms

        # close the dialog
        inmain(self.close)

    def _rename_function(self, selected, batches: list = None) -> None:
        if selected and len(selected) > 3 and isinstance(
                selected[2],
                SimpleItem
        ):
            symbol = selected[2].data

            function_addr = symbol["function_addr"] + self.base_addr
            original_name = symbol["org_func_name"]
            original_id = symbol["origin_function_id"]
            matched_name = symbol["nearest_neighbor_function_name_mangled"]
            confidence = symbol["confidence"]
            # nnfid = symbol["nearest_neighbor_id"]
            # nnbid = symbol["nearest_neighbor_binary_id"]
            # nn_is_debug = symbol["nearest_neighbor_debug"]

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
        if hasattr(self, "search_query") and self.search_query == query:
            return
        setattr(self, "search_query", query)
        try:
            query_data = self._parse_search_query(query)
            if not self._is_query_empty(query_data):
                self._search_collection(query_data)
            else:
                # empty resultTable
                inmain(
                    inmain(self.ui.collectionsTable.model).fill_table,
                    []
                )
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
    def _divide_chunks(data: list, n: int = 50) -> Generator[list, None, None]:
        # looping till length l
        for idx in range(0, len(data), n):
            yield data[idx: idx + n]
