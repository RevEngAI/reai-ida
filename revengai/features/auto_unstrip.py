from concurrent.futures import ThreadPoolExecutor
from reait.api import RE_nearest_symbols_batch, RE_analyze_functions
from requests import Response, HTTPError, RequestException
import idc
import logging
from revengai.misc.utils import IDAUtils
from idautils import Functions
from idaapi import get_imagebase
from revengai.misc.qtutils import inthread, inmain
from revengai.manager import RevEngState


logger = logging.getLogger("REAI")


@staticmethod
def _divide_chunks(data: list, n: int = 50) -> list:
    for idx in range(0, len(data), n):
        yield data[idx : idx + n]


class AutoUnstrip:
    def __init__(self, state: RevEngState):
        self.state = state
        self.base_addr = get_imagebase()
        self.analysed_functions = {}
        self.functions = self._get_all_functions()

        self._get_analysed_functions()
        self.function_ids = self._get_sync_analysed_ids_local()

    def _get_all_functions(self) -> list:
        functions = []
        for func_ea in Functions():
            start_addr = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
            if IDAUtils.is_in_valid_segment(start_addr):
                functions.append(
                    {
                        "name": IDAUtils.get_demangled_func_name(func_ea),
                        "start_addr": (start_addr - self.base_addr),
                        "end_addr": (
                            idc.get_func_attr(func_ea, idc.FUNCATTR_END)
                            - self.base_addr
                        ),
                    }
                )

        return functions

    def _get_analysed_functions(self) -> dict:
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
                    "An unexpected error occurred. Sorry for the " "inconvenience.",
                ),
            )

    def _get_sync_analysed_ids_local(self) -> list:
        function_ids = []

        for idx, func in enumerate(self._functions):
            idx += 1

            function_id = self.analyzed_functions.get(func["start_addr"], None)

            if function_id:
                function_ids.append(function_id)

        return function_ids

    def _get_all_auto_unstrip_matches(
        self, max_workers=1, distance=0.09999999999999998
    ):

        with ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="reai-batch"
        ) as executor:

            def worker(chunk: list[int]) -> any:
                try:
                    return RE_nearest_symbols_batch(
                        function_ids=chunk,
                        distance=distance,
                        debug_enabled=True,
                    ).json()["function_matches"]
                except Exception as ex:
                    return ex

            futures = {
                executor.submit(worker, chunk): chunk
                for chunk in _divide_chunks(
                    self.function_ids, self.state.project_cfg.get("chunk_size")
                )
            }

            for future, chunk in futures.items():
                res = future.result() if not future.cancelled() else None
                if not res:
                    continue

                for symbol in res:
                    func_addr = next(
                        (
                            func_addr
                            for func_addr, func_id in self.analysed_functions.items()
                            if symbol["origin_function_id"] == func_id
                        ),
                        None,
                    )

                    func_name = next(
                        (
                            function["name"]
                            for function in self._functions
                            if func_addr == function["start_addr"]
                            and "FUN_" not in function["name"]
                        ),
                        "Unknown",
                    )

                    if func_addr and "FUN_" not in func_name:
                        symbol["org_func_name"] = next(
                            (
                                function["name"]
                                for function in self._functions
                                if func_addr == function["start_addr"]
                            ),
                            "Unknown",
                        )

                        nnfn = symbol["nearest_neighbor_function_name"]
                        if nnfn != symbol["org_func_name"]:
                            logger.info(
                                "Found similar function '%s' with a confidence level of '%s",
                                nnfn,
                                str(symbol["confidence"]),
                            )

                            symbol["function_addr"] = func_addr
