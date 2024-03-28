# -*- coding: utf-8 -*-

from os import stat
from os.path import basename

import ida_kernwin
import idaapi
import idc
from ida_nalt import get_imagebase
from qtutils import inthread, inmain
from requests import HTTPError, Response, post, get

from reait.api import RE_upload, RE_analyse, RE_status, reveng_req, RE_logs, binary_id, re_bid_search
from revengai.features.auto_analyze import AutoAnalysisDialog

from revengai.gui.dialog import Dialog
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
        def do_work(path: str) -> None:
            if RevEngState.LIMIT > (stat(path).st_size // (1024 * 1024)):
                try:
                    inmain(idc.warning)
                    RE_upload(path)

                    RE_analyse(fpath=path, model_name=state.config.get("model"), duplicate=True)
                except HTTPError as e:
                    inmain(Dialog.showInfo, "Upload Binary",
                           f"Error analysing {basename(path)}.\nReason: {e.response.json()['error']}")
            else:
                inmain(idc.warning,
                       f"The maximum size for uploading a binary should not exceed {RevEngState.LIMIT}MB.")

        inthread(do_work, idc.get_input_file_path())


def check_analyze(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def do_work(path: str) -> None:
            try:
                res: Response = RE_status(fpath=path)

                if isinstance(res, Response):
                    inmain(Dialog.showInfo, "Check Analysis Status", f"Status: {res.json()['status']}")
                else:
                    inmain(Dialog.showError, "Check Analysis Status", "No matches found.")
            except HTTPError:
                inmain(Dialog.showError, "Check Analysis Status",
                       "Error getting status\n\nCheck:\n"
                       "  • You have downloaded your binary id from the portal.\n"
                       "  • You have uploaded the current binary to the portal.")

        inthread(do_work, idc.get_input_file_path())


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
        def do_work(pseudo_code: str) -> None:
            if len(pseudo_code) > 0:
                try:
                    res: Response = reveng_req(post, "explain", data=pseudo_code.split("\n"),
                                               params={"language": inmain(idaapi.get_file_type_name)})

                    res.raise_for_status()
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

        inthread(do_work, IDAUtils.decompile_func(idc.here()))


def download_logs(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def do_work(path: str) -> None:
            try:
                res = RE_logs(path, False)

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

        inthread(do_work, idc.get_input_file_path())


def function_signature(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        def do_work(path: str) -> None:
            try:
                start_addr = inmain(idc.get_func_attr(inmain(idc.here()), idc.FUNCATTR_START))

                if start_addr is not idc.BADADDR:
                    start_addr -= inmain(get_imagebase())

                    bin_id = binary_id(path)
                    bid = re_bid_search(bin_id)

                    if bid > 0:
                        res: Response = reveng_req(get, f"analyse/functions/{bid}")

                        res.raise_for_status()

                        for item in res.json():
                            if item["function_vaddr"] == start_addr:
                                res = reveng_req(post, "functions/dump",
                                                 json_data={"function_id_list": [item["function_id"]]})

                                res.raise_for_status()

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

        inthread(do_work, idc.get_input_file_path())
