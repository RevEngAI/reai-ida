# -*- coding: utf-8 -*-
import logging

import ida_kernwin
import idaapi
import idautils
import idc
from ida_nalt import get_imagebase

from os import stat
from subprocess import run
from requests import HTTPError, Response
from os.path import basename, getsize, isfile

from reait.api import RE_upload, RE_analyse, RE_status, RE_logs, re_binary_id, RE_functions_rename

from revengai.api import RE_explain, RE_analyze_functions, RE_functions_dump, RE_search, RE_recent_analysis
from revengai.misc.qtutils import inthread, inmain
from revengai.gui.dialog import Dialog, StatusForm
from revengai.manager import RevEngState
from revengai.features.auto_analyze import AutoAnalysisDialog
from revengai.features.function_similarity import FunctionSimilarityDialog
from revengai.misc.utils import IDAUtils
from revengai.wizard.wizard import RevEngSetupWizard


logger = logging.getLogger("REAI")


def setup_wizard(state: RevEngState) -> None:
    RevEngSetupWizard(state).exec_()


def upload_binary(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        def bg_task(path: str, syms: dict) -> None:
            if state.config.LIMIT > (stat(path).st_size // (1024 * 1024)):
                try:
                    inmain(idaapi.show_wait_box, "HIDECANCEL\nUploading binary for analysis…")

                    res = RE_upload(path)

                    upload = res.json()

                    logger.info("Upload ended for: %s. %s", basename(path), upload["message"])

                    if upload["success"]:
                        sha_256_hash = upload["sha_256_hash"]

                        inmain(state.config.database.add_upload, path, sha_256_hash)

                        res: Response = RE_analyse(fpath=path, binary_size=getsize(path),
                                                   model_name=state.config.get("model"), symbols=syms, duplicate=True)

                        analysis = res.json()

                        state.config.set("binary_id", analysis["binary_id"])

                        inmain(state.config.database.add_analysis,
                               sha_256_hash, analysis["binary_id"], analysis["success"])

                        logger.info("Binary analysis %s for: %s",
                                    "succeed" if analysis["success"] else "failed", basename(path))
                except HTTPError as e:
                    logger.error("Error analyzing %s. Reason: %s", basename(path), e)
                    inmain(idaapi.hide_wait_box)
                    inmain(idc.warning, f"Error analysing {basename(path)}.\nReason: {e.response.json()['error']}")
                else:
                    inmain(idaapi.hide_wait_box)
            else:
                inmain(idc.warning,
                       f"Please be advised that the largest size for processing a binary file is"
                       f" {state.config.LIMIT} MB.")

        symbols: dict = {"base_addr": get_imagebase()}

        functions = []

        for func_ea in idautils.Functions():
            functions.append({"name": idc.get_func_name(func_ea),
                              "start_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_START),
                              "end_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_END)})

        symbols["functions"] = functions

        inthread(bg_task, fpath, symbols)


def check_analyze(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        state.config.init_current_analysis()

        def bg_task() -> None:
            try:
                bid = state.config.get("binary_id", 0)

                res: Response = RE_status(fpath, bid)

                status = res.json()["status"]

                if bid:
                    inmain(state.config.database.update_analysis, bid, status)

                logger.info("Got binary analysis status: %s", status)
                inmain(Dialog.showInfo, "Check Binary Analysis Status", f"Binary analysis status: {status}")
            except HTTPError as e:
                if "error" in e.response.json():
                    logger.error("Error getting binary analysis status: %s", e.response.json()["error"])
                else:
                    logger.error("Error getting binary analysis status: %s", e)

                inmain(Dialog.showError, "Check Binary Analysis Status",
                       """Error getting binary analysis status.\n\nPlease check:
    • You have downloaded your binary ID from the portal.
    • You have uploaded the current binary to the portal.""")

        inthread(bg_task)


def auto_analyze(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        def bg_task() -> None:
            done, status = is_analysis_complete(state, fpath)
            if done:
                dialog = inmain(AutoAnalysisDialog, state, fpath)
                inmain(dialog.exec_)
            else:
                inmain(idc.warning, f"Binary analysis status: {status}")

        inthread(bg_task)


def rename_function(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if not state.config.is_valid():
        setup_wizard(state)
    elif not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        def bg_task() -> None:
            done, status = is_analysis_complete(state, fpath)
            if done:
                dialog = inmain(FunctionSimilarityDialog, state, fpath)
                inmain(dialog.exec_)
            else:
                inmain(idc.warning, f"Binary analysis status: {status}")

        inthread(bg_task)


def explain_function(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        state.config.init_current_analysis()

        def bg_task(pseudo_code: str) -> None:
            if len(pseudo_code) > 0:
                try:
                    # Gets the programming language from the current binary
                    ret = run(f"rabin2 -I {fpath} | grep 'lang '", shell=True, capture_output=True)

                    res: Response = RE_explain(pseudo_code,
                                               ret.stdout.split(b' ')[-1].strip().decode() if ret.returncode == 0 else None)

                    if "error" in res.json():
                        error = res.json()["error"]

                        logger.error("Error with function explanation: %s", error)
                        inmain(Dialog.showError, "", f"Error getting function explanation: {error}")
                    else:
                        comment = f"RevEng.AI Autogenerated\n\n{res.json()['explanation']}"

                        logger.info(comment)
                        inmain(IDAUtils.set_comment, inmain(idc.here), comment)
                except HTTPError as e:
                    logger.error("Error with function explanation: %s", e)
                    if "error" in e.response.json():
                        inmain(Dialog.showError, "Function Explanation",
                               f"Error getting function explanation: {e.response.json()['error']}")
            else:
                info = inmain(idaapi.get_inf_structure)

                procname = info.procname.lower()
                bits = 64 if inmain(info.is_64bit) else 32 if inmain(info.is_32bit) else 16

                # https://github.com/williballenthin/python-idb/blob/master/idb/idapython.py#L955-L1046
                if any(procname.startswith(arch) for arch in ("metapc", "athlon", "k62", "p2", "p3", "p4", "80",)):
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

                logger.warning("Hex-Rays %s decompiler is not available", arch)
                inmain(idc.warning, f"Hex-Rays {arch} decompiler is not available.")

        inthread(bg_task, IDAUtils.decompile_func(idc.here()))


def download_logs(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        state.config.init_current_analysis()

        def bg_task() -> None:
            try:
                res = RE_logs(fpath, console=False, binary_id=state.config.get("binary_id", 0))

                if res.json()["success"]:
                    filename = inmain(ida_kernwin.ask_file, 1, "*.log", "Output Filename:")

                    if filename:
                        with open(filename, "w") as fd:
                            fd.write(res.json()["logs"])
                    else:
                        logger.warning("No output directory provided to export logs to")
                        inmain(idc.warning, "No output directory provided to export logs to.")
                else:
                    logger.warning("No binary analysis logs found for: %s", basename(fpath))
                    inmain(idc.warning, f"No binary analysis logs found for: {basename(fpath)}.")
            except HTTPError as e:
                logger.error("Unable to download binary analysis logs for: %s. Reason: %s",
                             basename(fpath), e)

                if "error" in e.response.json():
                    inmain(Dialog.showError, "Binary Analysis Logs",
                           f"Unable to download binary analysis logs: {e.response.json()['error']}")

        inthread(bg_task)


def function_signature(state: RevEngState, func_addr: int = 0) -> None:
    fpath = idc.get_input_file_path()

    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        state.config.init_current_analysis()

        def bg_task(start_addr: int) -> None:
            try:
                if start_addr is not idc.BADADDR:
                    start_addr -= inmain(get_imagebase)

                    res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

                    for function in res.json():
                        if function["function_vaddr"] == start_addr:
                            res = RE_functions_dump([function["function_id"]])

                            dump = res.json()[0]

                            # TODO Manage information of function arguments
                            params = dump["params"]
                            if dump["returns"]:
                                return_type = dump["return_type"]

                                # newtype = return_type
                                #
                                # if idc.SetType(start_addr, ""):
                                #     logger.info("New function signature for 0x%X is '%s'",
                                #                    start_addr, newtype)
                                # else:
                                #     logger.warning("Failed to set function type '%s' defined at address 0x%X",
                                #                    newtype, start_addr)
                            break
            except HTTPError as e:
                logger.error("Unable to obtain function argument details. %s", e)

                if "error" in e.response.json():
                    inmain(Dialog.showError, "Binary Analysis Logs",
                           f"Failed to obtain function argument details: {e.response.json()['error']}")

        inthread(bg_task, idc.get_func_attr(func_addr if func_addr > 0 else idc.here(), idc.FUNCATTR_START))


def analysis_history(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        state.config.init_current_analysis()

        def bg_task() -> None:
            try:
                res = RE_search(fpath)

                binaries = []
                results = list(filter(lambda binary: binary is not None, res.json()["query_results"]))
                for binary in results:
                    binaries.append([binary.get("binary_name"), str(binary["binary_id"]),
                                     binary["status"], binary["creation"]])

                    inmain(state.config.database.add_analysis,
                           binary["sha_256_hash"], binary["binary_id"], binary["status"], binary["creation"])

                if len(binaries):
                    f = inmain(StatusForm, state, binaries)
                    inmain(f.Compile)
                    inmain(f.Execute)
                else:
                    logger.info("%s not yet analyzed", basename(fpath))
                    inmain(Dialog.showInfo, "Binary Analysis History",
                           f"{basename(fpath)} binary not yet analyzed.")
            except HTTPError as e:
                logger.error("Unable to obtain binary analysis history. %s", e)
                if "error" in e.response.json():
                    inmain(Dialog.showError, "Binary Analysis History",
                           f"Failed to obtain binary analysis history: {e.response.json()['error']}")

        inthread(bg_task)


def load_recent_analyses(state: RevEngState) -> None:
    if state.config.is_valid():
        state.config.init_current_analysis()

        def bg_task(fpath: str) -> None:
            try:
                res: Response = RE_recent_analysis()

                for analysis in res.json()["analysis"]:
                    inmain(state.config.database.add_upload, analysis["binary_name"], analysis["sha_256_hash"])
                    inmain(state.config.database.add_analysis, analysis["sha_256_hash"],
                           analysis["binary_id"], analysis["status"], analysis["creation"], analysis["model_name"])

                if fpath and isfile(fpath):
                    state.config.set("binary_id",
                                     inmain(state.config.database.get_last_analysis, re_binary_id(fpath)))
                else:
                    state.config.set("binary_id", None)
            except HTTPError as e:
                logger.error("Error getting recent analyses: %s", e)
            else:
                inmain(sync_functions_name, state)

        inthread(bg_task, idc.get_input_file_path())


def sync_functions_name(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if state.config.is_valid() and fpath and isfile(fpath):
        state.config.init_current_analysis()

        def bg_task() -> None:
            try:
                res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

                for function in res.json():
                    fe = next((func for func in functions if function["function_vaddr"] == func["start_addr"]), None)

                    if fe and fe["name"] != function["function_name"]:
                        try:
                            RE_functions_rename(function["function_id"], fe["name"])
                        except HTTPError as e:
                            logger.warning("Failed to sync functionId %d. %s",
                                           function["function_id"], e.response.reason)
            except HTTPError as e:
                logger.error("Error syncing functions: %s", e)

        functions = []

        for func_ea in idautils.Functions():
            functions.append({"name": idc.get_func_name(func_ea),
                              "start_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_START)})

        inthread(bg_task)


def is_analysis_complete(state: RevEngState, fpath: str) -> tuple[bool, str]:
    try:
        bid = state.config.get("binary_id", 0)

        res: Response = RE_status(fpath, bid)

        status = res.json()["status"]

        if bid:
            inmain(state.config.database.update_analysis, bid, status)

        return status == "Complete", status
    except HTTPError as e:
        if "error" in e.response.json():
            msg = e.response.json()["error"]

            if "invalid" in msg.lower():
                upload_binary(state)

            logger.error("Error getting binary analysis status: %s", msg)
        else:
            logger.error("Error getting binary analysis status: %s", e)

        return False, "Processing"
