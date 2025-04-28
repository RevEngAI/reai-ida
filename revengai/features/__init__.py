import abc
import logging
from concurrent.futures import as_completed, ThreadPoolExecutor
from itertools import islice
from os.path import dirname, join
from typing import Generator

import idaapi
from PyQt5.QtCore import QRect
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QDialog, QDesktopWidget
from idaapi import get_imagebase
from reait.api import (
    RE_analyze_functions,
    RE_functions_rename,
    RE_functions_rename_batch,
)
from requests import HTTPError, Response, RequestException

from revengai.manager import RevEngState
from revengai.misc.qtutils import inthread, inmain


logger = logging.getLogger("REAI")


class BaseDialog(QDialog):
    __metaclass__ = abc.ABCMeta

    # Delay, in milliseconds, between the user finishing typing and the search
    # being performed
    searchDelay = 300

    def __init__(self, state: RevEngState, fpath: str, analyse: bool = True):
        QDialog.__init__(self)

        self.path = fpath
        self.state = state
        self.analyse = analyse
        self.analyzed_functions = {}

        self.base_addr = get_imagebase()

        # self.typing_timer = QTimer(self)
        # self.typing_timer.setSingleShot(
        #     True
        # )  # Ensure the timer will fire only once after it was started
        # self.typing_timer.timeout.connect(self._filter_collections)

        self.setModal(True)
        self.setWindowIcon(
            QIcon(join(dirname(__file__), "..", "resources", "favicon.png"))
        )

    def _is_query_empty(self, query: dict) -> bool:
        """
        Check if the query dictionary is empty or contains only None values.

        Args:
            query (dict): The query dictionary to check

        Returns:
            bool: True if the query is empty, False otherwise
        """
        return all(value is None for value in query.values())

    def _parse_search_query(self, query):
        """
        Parse a search query with special selectors.

        Args:
            query (str): The search query string to parse

        Returns:
            dict: A dictionary containing parsed query components

        Raises:
            ValueError: If multiple non-tag selectors or a selector with raw
                        query are used
        """
        # Initialize the result dictionary with default empty values
        result = {
            'query': None,
            'sha_256_hash': None,
            'tags': None,
            'binary_name': None,
            'collection_name': None,
            'function_name': None,
            'model_name': None
        }

        # List of possible selectors (excluding 'tag')
        single_selectors = [
            'sha_256_hash',
            'binary_name',
            'collection_name',
            'function_name',
            'model_name'
        ]

        # Parse selector-based queries
        def extract_selector_value(query, selector):
            """Helper function to extract selector value"""
            selector_pattern = f"{selector}:"
            selector_match = query.find(selector_pattern)

            if selector_match != -1:
                # Extract the value after the selector
                start = selector_match + len(selector_pattern)
                end = query.find(' ', start)

                # If no space found, take till the end of string
                if end == -1:
                    end = len(query)

                # Extract the value and the full selector part
                value = query[start:end].strip()
                full_selector_part = query[selector_match:end].strip()

                return value, full_selector_part

            return None, None

        # Process tags first (can be multiple)
        def process_tags(query):
            tags = []
            while True:
                tag_value, tag_part = extract_selector_value(query, 'tag')
                if not tag_value:
                    break
                tags.append(tag_value)
                query = query.replace(tag_part, '').strip()
            if len(tags) == 0:
                tags = None
            return tags, query

        # Process tags
        result['tags'], query = process_tags(query)

        # Process other single selectors
        for selector in single_selectors:
            value, selector_part = extract_selector_value(query, selector)

            if value:
                # Check if this selector was already set
                if result[selector] is not None:
                    raise ValueError(
                        f"Only one {selector} selector can be used.")

                result[selector] = value
                query = query.replace(selector_part, '').strip()

        # Validation checks for additional text
        query = query.strip()
        if query:
            # If query is not empty after removing selectors
            if any(result[selector] is not None for selector in
                   single_selectors):
                raise ValueError(
                    "Selector cannot be used with additional text.")
            # If no other selectors, treat as raw query
            result['query'] = query

        return result

    def showEvent(self, event):
        super(BaseDialog, self).showEvent(event)

        screen: QRect = QDesktopWidget().screenGeometry()

        # Center the dialog to screen
        self.move(
            screen.width() // 2 - self.width() // 2,
            screen.height() // 2 - self.height() // 2,
        )

        if self.analyse:
            inthread(self._get_analyze_functions)

    def closeEvent(self, event):
        super(BaseDialog, self).closeEvent(event)

        self.analyzed_functions.clear()

    def _get_analyze_functions(self) -> None:
        try:
            res: Response = RE_analyze_functions(
                self.path, self.state.config.get("binary_id", 0)
            )

            for function in res.json()["functions"]:
                self.analyzed_functions[function["function_vaddr"]] = function[
                    "function_id"
                ]
        except HTTPError as e:
            logger.error(
                "Error getting analysed functions: %s",
                e.response.json().get(
                    "error",
                    "An unexpected error occurred. Sorry for the "
                    "inconvenience.",
                ),
            )

    def _function_rename(
            self, func_addr: int, new_func_name: str, func_id: int = 0
    ) -> None:
        if not func_id:
            func_id = self._get_function_id(func_addr)

        if func_id:
            try:
                res: Response = RE_functions_rename(func_id, new_func_name)

                logger.info(res.json()["msg"])
            except HTTPError as e:
                error = e.response.json().get(
                    "error",
                    "An unexpected error occurred. Sorry for the "
                    "inconvenience.",
                )
                logger.error(
                    "Failed to rename functionId %d by '%s'. %s",
                    func_id,
                    new_func_name,
                    error,
                )

                inmain(idaapi.warning, error)
        else:
            logger.error("Not found functionId at address: 0x%X.", func_addr)

    def _batch_function_rename(self, functions: dict[int, str]) -> None:
        max_workers = 1

        if self.state.project_cfg.get("parallelize_query"):
            max_workers = self.state.project_cfg.get("max_workers")

        with ThreadPoolExecutor(
                max_workers=max_workers, thread_name_prefix="reai-batch"
        ) as executor:

            def worker(chunk: dict[int, str]) -> any:
                try:
                    return RE_functions_rename_batch(chunk)
                except RequestException as ex:
                    return ex

            # Start the functions renaming batch operations and mark each
            # future with its chunk
            futures = [
                executor.submit(worker, chunk)
                for chunk in BaseDialog._divide_chunks(
                    functions, self.state.project_cfg.get("chunk_size")
                )
            ]

            for future in as_completed(futures):
                try:
                    data = future.result()

                    if isinstance(data, Response):
                        logger.info(data.json())
                    else:
                        logger.error(
                            "Failed to rename function in batch mode. %s", data
                        )
                except Exception as e:
                    logger.error("Exception raised: %s", e)

            # inmain(
            #     idaapi.info,
            #     "Completed batch renaming of functions. "
            #     "Check the log for details."
            # )

    def _function_breakdown(self, func_id: int) -> None:
        # Prevent circular import
        from revengai.actions import function_breakdown

        function_breakdown(self.state, func_id)

    def _generate_summaries(self, func_id: int) -> None:
        # Prevent circular import
        from revengai.actions import generate_summaries

        generate_summaries(self.state, func_id)

    def _get_function_id(self, func_addr: int) -> int:
        return self.analyzed_functions.get(func_addr, 0)

    def _filter_collections(self):
        pass

    @staticmethod
    def _divide_chunks(data: dict, n: int = 50) -> Generator[dict, None, None]:
        it = iter(data.items())
        for _ in range(0, len(data), n):
            yield dict(islice(it, n))
