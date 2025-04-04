import abc
import logging
from concurrent.futures import as_completed, ThreadPoolExecutor
from itertools import islice
from os.path import dirname, join
from typing import Generator

import idaapi
from PyQt5.QtCore import QRect, QTimer
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QDialog, QDesktopWidget
from idaapi import get_imagebase
from reait.api import (
    RE_analyze_functions,
    RE_functions_rename,
    RE_functions_rename_batch,
    RE_analysis_lookup,
    RE_generate_data_types,
    RE_list_data_types,
)
from requests import HTTPError, Response, RequestException

from libbs.api import DecompilerInterface
from libbs.artifacts import load_many_artifacts
from libbs.artifacts import _art_from_dict
from libbs.artifacts import ArtifactFormat
from libbs.artifacts import (
    Function,
    GlobalVariable,
    Enum,
    Struct,
    Typedef,
)
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

        self.typing_timer = QTimer(self)
        self.typing_timer.setSingleShot(
            True
        )  # Ensure the timer will fire only once after it was started
        self.typing_timer.timeout.connect(self._filter_collections)

        self.setModal(True)
        self.setWindowIcon(
            QIcon(join(dirname(__file__), "..", "resources", "favicon.png"))
        )

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

    def _function_import_symbol_datatypes(
            self,
            matched_function_bid: int = 0,
            matched_func_id: int = 0,
            function_addr: int = 0
    ) -> None:
        def apply_type(deci: DecompilerInterface, artifact) -> None | str:
            supported_types = [Function, GlobalVariable, Enum, Struct, Typedef]

            if not any(isinstance(artifact, t) for t in supported_types):
                return "Unsupported artifact type: " \
                       f"{artifact.__class__.__name__}"

            if isinstance(artifact, Function):
                deci.functions[artifact.addr] = artifact
            elif isinstance(artifact, GlobalVariable):
                deci.global_vars[artifact.addr] = artifact
            elif isinstance(artifact, Enum):
                deci.enums[artifact.name] = artifact
            elif isinstance(artifact, Struct):
                deci.structs[artifact.name] = artifact
            elif isinstance(artifact, Typedef):
                deci.typedefs[artifact.name] = artifact

            return None

        def apply_types(
                deci: DecompilerInterface,
                artifacts: list
        ) -> None | str:
            for artifact in artifacts:
                error = apply_type(deci, artifact)
                if error is not None:
                    return error
            return None

        def _load_many_artifacts_from_list(artifacts: list[dict]) -> list:
            _artifacts = []
            for artifact in artifacts:
                art = _art_from_dict(artifact)
                if art is not None:
                    _artifacts.append(art)
            return _artifacts

        try:
            # first step is to get the analysis id for the function
            res: dict = RE_analysis_lookup(matched_function_bid).json()
            matched_analysis_id = res.get("analysis_id", 0)

            if matched_analysis_id == 0:
                logger.error(
                    "Failed to get analysis id for functionId %d.",
                    matched_func_id,
                )
                return

            # second step is to start the generation of the datatypes
            res = RE_generate_data_types(
                matched_analysis_id,
                [matched_func_id]
            ).json()
            status = res.get("status", False)

            if status:
                logger.info(
                    "Successfully started the generation of functions"
                    " data types"
                )
            else:
                logger.error(
                    "Failed to start the generation of functions data types"
                )
                return

            # try list the datatypes

            res: dict = RE_list_data_types(
                matched_analysis_id,
                [matched_func_id]
            ).json()

            status = res.get("status", False)

            if not status:
                logger.error("Error getting function data types")
                return

            # TODO: remove this
            logger.info(f"Let's stop here at the moment... {res}")
            return

            deci = DecompilerInterface.discover(force_decompiler="ida")
            if not deci:
                logger.error("Libbs: Unable to find a decompiler")
                return

            total_count = res.get("data", {}).get("total_count", 0)

            if total_count > 0:
                items = res.get("data", {}).get("items", [])
                for item in items:
                    function_types = item.get(
                        "data_types", {}).get("func_types", None)
                    func_deps = item.get(
                        "data_types", {}).get("func_deps", [])
                    function_id = item.get("function_id", 0)

                    if function_types and len(func_deps) > 0:

                        deps = _load_many_artifacts_from_list(
                            func_deps,
                        )

                        logger.info(
                            f"Loaded {len(func_deps)} for function "
                            f"{function_id}"
                        )

                        deps_res = apply_types(deci, deps)
                        if deps_res is not None:
                            logger.error(
                                "Error applying data type dependencies for "
                                f"function {function_id}: {deps_res}"
                            )
                            return
                        else:
                            logger.info(
                                "Applied data type dependencies for function "
                                f"id {function_id}"
                            )

                    if function_types:
                        func: Function = _art_from_dict(function_types)
                        # repalce function address with the one we need to
                        # apply the data type to
                        func.addr = function_addr
                        func_res = apply_type(deci, func)
                        if func_res is not None:
                            logger.error(
                                "Error applying function data type for "
                                f"function id {function_id}: {func_res}"
                            )
                            return
                        else:
                            logger.info(
                                "Applied data types for function id "
                                f"{function_id}"
                            )

                logger.info("Function data types application completed")
            else:
                logger.warning("No function data types to apply")

        except HTTPError as e:
            error = e.response.json().get(
                "error",
                f"An unexpected error occurred. Sorry for the "
                f"inconvenience. {e.response.status_code}",
            )

            logger.error(
                "Error while importing data types for functionId "
                f"{matched_func_id}: {error}"
            )

            inmain(idaapi.warning, error)

        except ValueError as e:
            logger.error(
                "Error while importing data types for functionId "
                f"{matched_func_id}: {e}"
            )

            inmain(idaapi.warning, str(e))

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
