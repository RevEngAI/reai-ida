# -*- coding: utf-8 -*-

from os import stat
from os.path import basename

import ida_kernwin
import idaapi
import idautils
import idc
from ida_nalt import get_imagebase
from qtutils import inthread, inmain
from requests import HTTPError, Response

from reait.api import RE_upload, RE_analyse, RE_status, RE_logs

from revengai.api import RE_explain, RE_analyze_functions, RE_functions_dump, RE_search
from revengai.features.auto_analyze import AutoAnalysisDialog

from revengai.gui.dialog import Dialog, StatusForm
from revengai.manager import RevEngState
from revengai.features.function_simularity import FunctionSimularityDialog
from revengai.misc.utils import IDAUtils
from revengai.wizard.wizard import RevEngSetupWizard


def setup_wizard(state: RevEngState) -> None:
    RevEngSetupWizard(state).exec_()


def upload_binary(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def bg_task(path: str, symbols: dict) -> None:
            if RevEngState.LIMIT > (stat(path).st_size // (1024 * 1024)):
                try:
                    inmain(idaapi.show_wait_box, "HIDECANCEL\nUploading binary for analysis…")

                    RE_upload(path)

                    RE_analyse(fpath=path, model_name=state.config.get("model"), symbols=symbols, duplicate=True)
                except HTTPError as e:
                    inmain(idaapi.hide_wait_box)
                    inmain(Dialog.showInfo, "Upload Binary",
                           f"Error analysing {basename(path)}.\nReason: {e.response.json()['error']}")
                else:
                    inmain(idaapi.hide_wait_box)
            else:
                inmain(idc.warning,
                       f"The maximum size for uploading a binary should not exceed {RevEngState.LIMIT}MB.")

        symbols: dict = {"base_addr": get_imagebase()}

        functions = []

        for func_ea in idautils.Functions():
            functions.append({"name": idc.get_func_name(func_ea),
                              "start_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_START),
                              "end_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_END)})

        symbols["functions"] = functions

        inthread(bg_task, idc.get_input_file_path(), symbols)


def check_analyze(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def bg_task(path: str) -> None:
            try:
                res: Response = RE_status(path)

                if isinstance(res, Response):
                    inmain(Dialog.showInfo, "Check Analysis Status", f"Status: {res.json()['status']}")
                else:
                    inmain(Dialog.showError, "Check Analysis Status", "No matches found.")
            except HTTPError:
                inmain(Dialog.showError, "Check Analysis Status",
                       "Error getting status\n\nCheck:\n"
                       "  • You have downloaded your binary id from the portal.\n"
                       "  • You have uploaded the current binary to the portal.")

        inthread(bg_task, idc.get_input_file_path())


def auto_analyze(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        dialog = AutoAnalysisDialog(state, idc.get_input_file_path())
        dialog.exec_()


def rename_function(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        dialog = FunctionSimularityDialog(state, idc.get_input_file_path())
        dialog.exec_()


def explain_function(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def bg_task(pseudo_code: str) -> None:
            if len(pseudo_code) > 0:
                try:
                    res: Response = RE_explain(pseudo_code, inmain(idaapi.get_file_type_name))

                    print(res.text)

                    # inmain(IDAUtils.set_comment, inmain(idc.here), res.json()["explanation"])
                except HTTPError as e:
                    if "error" in e.response.json():
                        inmain(Dialog.showError, "Function Explanation",
                               f"Error getting function explanation: {e.response.json()['error']}")
            else:
                info = inmain(idaapi.get_inf_structure)

                procname = info.procname.lower()
                bits = 64 if info.is_64bit() else 32 if info.is_32bit() else 16

                # https://github.com/williballenthin/python-idb/blob/master/idb/idapython.py#L955-L1046
                if any(procname.startswith(arch) for arch in ["metapc", "athlon", "k62", "p2", "p3", "p4", "80"]):
                    arch = "x86_64" if bits == 64 else "x86"
                elif procname.startswith("arm"):
                    arch = "ARM64" if bits == 64 else "ARM"
                elif procname.startswith("mips"):
                    arch = f"MIPS{bits}"
                elif procname.startswith("ppc"):
                    arch = f"PPC{bits}"
                elif procname.startswith("sparc"):
                    arch = f"SPARC{bits}"
                else:
                    arch = "unknown arch"

                inmain(idc.warning, f"Hex-Rays {arch} decompiler is not available.")

        inthread(bg_task, IDAUtils.decompile_func(idc.here()))


def download_logs(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def bg_task(path: str) -> None:
            try:
                res = RE_logs(path, console=False)

                if isinstance(res, Response) and len(res.text) > 0:
                    filename = inmain(ida_kernwin.ask_file, 1, "*.log", "Output Filename:")

                    if filename:
                        with open(filename, "w") as fd:
                            fd.write(res.text)
                else:
                    inmain(idc.warning, f"No binary analysis logs found for: {basename(path)}.")
            except HTTPError as e:
                if "error" in e.response.json():
                    inmain(Dialog.showError, "Binary Analysis Logs",
                           f"Unable to download binary analysis logs: {e.response.json()['error']}")

        inthread(bg_task, idc.get_input_file_path())


def function_signature(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def bg_task(path: str, start_addr: int) -> None:
            try:
                if start_addr is not idc.BADADDR:
                    start_addr -= inmain(get_imagebase())

                    res: Response = RE_analyze_functions(path)

                    for item in res.json():
                        if item["function_vaddr"] == start_addr:
                            res = RE_functions_dump([item["function_id"]])

                            dump = res.json()[0]

                            # TODO Manage information of function arguments
                            params = dump["params"]
                            if dump["returns"]:
                                return_type = dump["return_type"]

                            break
            except HTTPError as e:
                if "error" in e.response.json():
                    inmain(Dialog.showError, "Binary Analysis Logs",
                           f"Failed to obtain function argument details: {e.response.json()['error']}")

        inthread(bg_task, idc.get_input_file_path(), idc.get_func_attr(idc.here(), idc.FUNCATTR_START))


def analysis_history(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def bg_task(path: str) -> None:
            try:
                res = RE_search(path)

                binaries = []
                for binary in res.json()["binaries"]:
                    binaries.append([binary["binary_name"], str(binary["binary_id"]),
                                     binary["status"], binary["creation"]])

                f = inmain(StatusForm, binaries)
                inmain(f.Compile)
                inmain(f.Execute)
            except HTTPError as e:
                if "error" in e.response.json():
                    inmain(Dialog.showError, "Binary Analysis History",
                           f"Failed to obtain binary analysis history: {e.response.json()['error']}")

        inthread(bg_task, idc.get_input_file_path())
