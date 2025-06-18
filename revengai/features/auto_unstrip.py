from concurrent.futures import ThreadPoolExecutor
from reait.api import RE_nearest_symbols_batch, RE_analyze_functions
from requests import Response, HTTPError
import idc
import logging
from revengai.misc.utils import IDAUtils
from idautils import Functions
from idaapi import get_imagebase
from revengai.misc.qtutils import inmain
from revengai.manager import RevEngState


logger = logging.getLogger("REAI")


@staticmethod
def _divide_chunks(data: list, n: int = 50):
    for idx in range(0, len(data), n):
        yield data[idx: idx + n]


class AutoUnstrip:
    def __init__(self, state: RevEngState):
        self.state = state

        self.auto_unstrip_distance = 0.09999999999999998
        self.base_addr = get_imagebase()
        self.path = idc.get_input_file_path()

        self._analysed_functions = {}
        self._functions = self._get_all_functions()

        self._get_analysed_functions()
        self.function_ids = self._get_sync_analysed_ids_local()

    def _get_all_functions(self) -> list:
        functions = []
        for func_ea in Functions():
            start_addr = idc.get_func_attr(func_ea, idc.FUNCATTR_START)
            if IDAUtils.is_in_exec_segment(start_addr):
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
                self._analysed_functions[
                    function["function_vaddr"]
                ] = function["function_id"]
        except HTTPError as e:
            logger.error(
                "Error getting analysed functions: %s",
                e.response.json().get(
                    "error",
                    "An unexpected error occurred."
                    " Sorry for the inconvenience",
                ),
            )

    def _get_sync_analysed_ids_local(self) -> list:
        function_ids = []

        for idx, func in enumerate(self._functions):
            idx += 1

            function_id = self._analysed_functions.get(
                func["start_addr"], None)

            if function_id:
                function_ids.append(function_id)

        return function_ids

    def _get_all_auto_unstrip_rename_matches(self, max_workers=1):
        results = []
        with ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="reai-batch"
        ) as executor:

            def worker(chunk: list[int]) -> any:
                try:
                    ret = RE_nearest_symbols_batch(
                        function_ids=chunk,
                        distance=self.auto_unstrip_distance,
                        debug_enabled=True,
                    )

                    j = ret.json()
                    if 'function_matches' not in j:
                        raise ValueError

                    return j['function_matches']
                except Exception as e:
                    return e

            futures = {
                executor.submit(worker, chunk): chunk
                for chunk in _divide_chunks(
                    self.function_ids, self.state.project_cfg.get("chunk_size")
                )
            }

            for future, _ in futures.items():
                res = future.result() if not future.cancelled() else None
                if not res:
                    continue

                for symbol in res:
                    func_addr = next(
                        (
                            func_addr
                            for func_addr, func_id in
                            self._analysed_functions.items()
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
                        nnfnm = symbol["nearest_neighbor_function_name_mangled"]
                        if nnfn != symbol["org_func_name"]:
                            symbol["function_addr"] = func_addr

                            results.append(
                                {
                                    "target_func_addr": func_addr,
                                    "new_name_str": nnfnm
                                }
                            )
        return results

    def unstrip(self) -> int:
        matches = self._get_all_auto_unstrip_rename_matches()
        self._apply_all(matches)

        return len(matches)

    def _apply_all(self, result: list) -> None:
        for res in result:
            addr = self.base_addr + res["target_func_addr"]
            new_name = res["new_name_str"]
            logger.info(
                "Renaming function at 0x%X to %s",
                addr,
                new_name,
            )

            inmain(idc.set_name, addr, new_name)
            inmain(idc.set_func_flags, addr, idc.FUNC_LIB)
