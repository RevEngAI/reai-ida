import logging
from concurrent.futures import ThreadPoolExecutor
import idc
from PyQt5.QtCore import Qt, QModelIndex
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QMenu
from idaapi import hide_wait_box, show_wait_box, user_cancelled
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
from revengai.models.single_checkable_model import (
    RevEngSingleCheckableTableModel
)
from revengai.gui.custom_card import QRevEngCard
from revengai.ui.function_similarity_panel import Ui_FunctionSimilarityPanel
from datetime import datetime
from libbs.artifacts import _art_from_dict
from libbs.artifacts import (
    Function,
)
from libbs.api import DecompilerInterface

from revengai.misc.datatypes import (
    fetch_data_types,
    apply_data_types,
    apply_signature,
    wait_box_decorator,
)
import idaapi
from PyQt5.QtCore import QTimer

logger = logging.getLogger("REAI")


class FunctionSimilarityDialog(BaseDialog):
    def __init__(self, state: RevEngState, fpath: str):
        BaseDialog.__init__(self, state, fpath)

        start_addr = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)

        if start_addr is not idc.BADADDR:
            self.v_addr = start_addr - self.base_addr
        else:
            logger.error("Pointer location not in valid function")
            Dialog.showError(
                "Find Similar Functions", "Cursor position not in a function."
            )

        self.ui = Ui_FunctionSimilarityPanel()
        self.ui.setupUi(self)

        self.ui.renameButton.setEnabled(False)
        self.ui.layoutFilter.register_cb(self._callback)
        self.ui.searchButton.clicked.connect(self._filter_collections)
        self.ui.searchQuery.returnPressed.connect(
            self._filter_collections
        )
        self.ui.tabWidget.tabBarClicked.connect(self._tab_changed)
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

        self.ui.resultsTable.horizontalHeader().setDefaultAlignment(
            Qt.AlignCenter
        )

        self.ui.resultsTable.setModel(
            RevEngSingleCheckableTableModel(
                data=[],
                parent=self,
                columns=[0],
                header=[
                    "Selected",
                    "Original Function Name",
                    "Matched Function Name",
                    "Signature",
                    "Matched Binary",
                    "Similarity",
                    "Confidence",
                ],
            )
        )

        self.ui.resultsTable.customContextMenuRequested.connect(
            self._table_menu
        )

        self.ui.confidenceSlider.valueChanged.connect(self._confidence)
        self.ui.fetchResultsButton.clicked.connect(self._fetch)
        self.ui.renameButton.clicked.connect(self._rename_symbol)
        self.ui.fetchDataTypesButton.clicked.connect(self._fetch_data_types)

        self._confidence(self.ui.confidenceSlider.sliderPosition())

        self._fetch_timer = None
        self._fetch_executor = None
        self._fetch_future = None

    def showEvent(self, event):
        super(FunctionSimilarityDialog, self).showEvent(event)
        inthread(self._search_collection)

    def closeEvent(self, event):
        super(FunctionSimilarityDialog, self).closeEvent(event)

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
        "HIDECANCEL\nGetting data types…"
    )
    def _fetch_data_types(self, *args) -> None:
        try:
            # get the model from the result table
            data = self.ui.resultsTable.model().get_datas()
            # loop all rows in the table
            function_ids = []
            for element in data:
                check_item: CheckableItem = element[0]
                # get the function id from the table
                function_id = check_item.data.get(
                    "nearest_neighbor_id",
                    None
                )
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
        except HTTPError as e:
            resp = e.response.json()
            error = resp.get("message", "Unexpected error occurred.")
            logger.error(
                "Error while fetching data types for the specified function:"
                f"{error}"
            )

    def _fetch(self):
        if self.v_addr != idc.BADADDR:
            inthread(
                self._load,
                self._selected_collections(),
                (100 - int(self.ui.confidenceSlider.property("value"))) / 100,
            )

    def _load(self, filter_data: dict, distance: float = 0.1):
        data = []
        try:
            model = inmain(self.ui.resultsTable.model)

            inmain(model.fill_table, [])
            inmain(self.ui.fetchResultsButton.setEnabled, False)
            inmain(self.ui.renameButton.setEnabled, False)
            inmain(self.ui.progressBar.setProperty, "value", 25)
            inmain(show_wait_box, "HIDECANCEL\nGetting results…")

            if not self.analyzed_functions or \
                    len(self.analyzed_functions) == 0:
                self._get_analyze_functions()

            function_id = self.analyzed_functions.get(self.v_addr, None)

            func_name = inmain(
                IDAUtils.get_demangled_func_name, self.v_addr +
                self.base_addr
            )

            if function_id is None:
                inmain(idc.warning, f"No matches found for {func_name}.")
                logger.error("No similar functions found for: %s", func_name)
                return

            inmain(self.ui.progressBar.setProperty, "value", 50)

            nb_results = inmain(self.ui.spinBox.text)

            res: dict = RE_nearest_symbols_batch(
                function_ids=[function_id],
                distance=distance,
                collections=filter_data["collections"],
                binaries=filter_data["binaries"],
                nns=nb_results,
                debug_enabled=inmain(self.ui.checkBox.isChecked)
            ).json()

            inmain(self.ui.progressBar.setProperty, "value", 75)

            matches = res.get("function_matches", [])

            for function in matches:

                nnbn = function["nearest_neighbor_binary_name"]
                similarity = function["confidence"] * 100
                nnfn = function["nearest_neighbor_function_name"]

                function["function_addr"] = self.v_addr + self.base_addr
                function["function_id"] = function_id
                try:
                    logger.info(f"Getting name score for {distance}")
                    name_score = RE_name_score(
                        [{"function_id": function_id, "function_name": nnfn}]
                    ).json()["data"]
                    confidence = name_score[0]["box_plot"]["average"]
                    if confidence < (100 - (distance * 100)):
                        logger.info(
                            f"Skipping {nnfn} because it's not similar"
                            f" enough to {nnfn}"
                        )
                        continue
                except Exception as e:
                    confidence = 0
                    logger.error(f"Error: {e}")

                data.append(
                    (
                        CheckableItem(
                            checked=False,
                            data=function,
                        ),
                        func_name,
                        nnfn,
                        SimpleItem(
                            text="N/A",
                            data=None,
                        ),
                        nnbn,
                        f"{similarity:.2f}%",
                        f"{confidence:.2f}%",
                    )
                )

            inmain(model.fill_table, data)
            inmain(self.ui.renameButton.setEnabled, len(data) > 0)
            inmain(self.ui.fetchDataTypesButton.setEnabled, len(data) > 0)

            if len(data) == 0:
                inmain(
                    idc.warning,
                    "No matches found. Try a different confidence value."
                )
                logger.error(
                    "No similar functions found for: %s with confidence: %d",
                    inmain(IDAUtils.get_demangled_func_name, inmain(idc.here)),
                    (1 - distance) * 100,
                )
        except HTTPError as e:
            import traceback as tb
            logger.error(f"Error: {e} \n{tb.format_exc()}")
            error = e.response.json().get(
                "error", "An unexpected error occurred. Sorry for the "
                         "inconvenience."
            )
            Dialog.showError("Function Renaming", error)
        except RequestException as e:
            logger.error("An unexpected error has occurred. %s", e)
        finally:
            inmain(hide_wait_box)
            inmain(self.ui.progressBar.setProperty, "value", 0)
            inmain(self.ui.fetchResultsButton.setEnabled, True)
            if len(data) > 0:
                inmain(self._tab_changed, 1)
                inmain(self.ui.tabWidget.setCurrentIndex, 1)
                width: int = inmain(self.ui.resultsTable.width)
                # Selected
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
                       3, round(width * 0.32))
                # Matched Binary
                inmain(self.ui.resultsTable.setColumnWidth,
                       4, round(width * 0.2))
                # Confidence
                inmain(self.ui.resultsTable.setColumnWidth,
                       5, round(width * 0.08))

    @wait_box_decorator(
        "HIDECANCEL\nApplying function name and data types…"
    )
    def _rename_symbol(self, *args) -> None:
        checked_elements = []

        data = self.ui.resultsTable.model().get_datas()
        for row in range(len(data)):
            check_item: CheckableItem = data[row][0]
            if check_item.checkState == Qt.Checked:
                checked_elements.append((data[row], row))

        if len(checked_elements) == 0:
            inmain(idc.warning, "No function selected.")
            return

        # this should be impossible, but just in case...
        if len(checked_elements) > 1:
            inmain(idc.warning, "Multiple functions selected.")
            return

        el, row = checked_elements[0]
        symbol = el[0].data
        signature = el[3].data
        nnfn = symbol['nearest_neighbor_function_name_mangled']
        addr = symbol['function_addr']

        if IDAUtils.set_name(addr, nnfn):
            if signature:
                deci = DecompilerInterface.discover(force_decompiler="ida")
                apply_data_types(
                    addr,
                    signature,
                    deci
                )
            else:
                logger.info(
                    "No signature found for the function. Skipping."
                )

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
            self.ui.confidenceSlider.hide()
            self.ui.progressBar.hide()
            self.ui.description.setVisible(False)

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

    def _table_menu(self) -> None:
        rows = sorted(
            set(index.row()
                for index in self.ui.resultsTable.selectedIndexes())
        )
        selected = self.ui.resultsTable.model().get_data(rows[0])

        if (
                selected
                and self.ui.renameButton.isEnabled()
                and isinstance(selected[0], SimpleItem)
        ):
            menu = QMenu()
            # renameAction = menu.addAction(self.ui.renameButton.text())
            # renameAction.triggered.connect(self._rename_symbol)

            func_id = selected[0].data["nearest_neighbor_id"]
            breakdownAction = menu.addAction("View Function Breakdown")
            breakdownAction.triggered.connect(
                lambda: self._function_breakdown(func_id))

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

            # summariesAction = menu.addAction("Generate AI Summaries")
            # summariesAction.triggered.connect(
            # lambda: self._generate_summaries(func_id))

            menu.exec_(QCursor.pos())

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

    def _selected_collections(self) -> dict:
        collections = []
        binaries = []
        for idx in range(self.ui.layoutFilter.count()):
            item: QRevEngCard = self.ui.layoutFilter.itemAt(idx).widget()
            data = item.custom_data
            if data["is_collection"]:
                collections.append(data["item_id"])
            else:
                binaries.append(data["item_id"])
        return {
            "collections": collections,
            "binaries": binaries,
        }

    def _confidence(self, value: int) -> None:
        self.ui.description.setText(f"Confidence: {value:#02d}")

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

        logger.info(f"State changed: {item}")

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
