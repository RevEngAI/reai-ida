# -*- coding: utf-8 -*-
import logging

import idautils
import idc
from idaapi import ask_file, get_imagebase, get_inf_structure, retrieve_input_file_size, show_wait_box, hide_wait_box

from subprocess import run
from threading import Timer

from requests import get, HTTPError, Response, RequestException
from os.path import basename, isfile
from datetime import date, datetime, timedelta

from reait.api import RE_upload, RE_analyse, RE_status, RE_logs, re_binary_id, RE_analyze_functions, file_type, \
    RE_functions_rename

from revengai import __version__
from revengai.api import RE_explain, RE_functions_dump, RE_search, RE_recent_analysis
from revengai.features.sync_functions import SyncFunctionsDialog
from revengai.misc.qtutils import inthread, inmain
from revengai.gui.dialog import Dialog, StatusForm, UploadBinaryForm, AboutForm, UpdateForm
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

    if is_condition_met(state, fpath) and is_file_supported(state, fpath):
        def bg_task(model: str, tags: list = None, scope: str = "PRIVATE", debug_fpath: str = None) -> None:
            file_size = inmain(retrieve_input_file_size)

            if state.config.LIMIT > file_size:
                try:
                    inmain(show_wait_box, "HIDECANCEL\nUploading binary for analysis…")

                    res: Response = RE_upload(fpath)

                    upload = res.json()

                    logger.info("Upload ended for: %s. %s", basename(fpath), upload["message"])

                    if upload["success"]:
                        sha_256_hash = upload["sha_256_hash"]

                        inmain(state.config.database.add_upload, fpath, sha_256_hash)

                        res = RE_analyse(fpath=fpath, binary_scope=scope,
                                         debug_fpath=debug_fpath, model_name=model,
                                         tags=tags, symbols=symbols, duplicate=True)

                        analysis = res.json()

                        state.config.set("binary_id", analysis["binary_id"])

                        inmain(state.config.database.add_analysis,
                               sha_256_hash, analysis["binary_id"], analysis["success"])

                        logger.info("Binary analysis %s for: %s",
                                    "succeed" if analysis["success"] else "failed", basename(fpath))

                        # Periodically check the status of the uploaded binary
                        def _worker(binary_id: int, delay: float = 60):
                            try:
                                status = RE_status(fpath, binary_id).json()["status"]

                                if status == "Processing":
                                    Timer(delay, _worker, args=(binary_id, delay,)).start()
                            except RequestException as ex:
                                logger.error("Error getting binary analysis status. Reason: %s", ex)

                        Timer(60, _worker, args=(analysis["binary_id"],)).start()
                except RequestException as e:
                    logger.error("Error analyzing %s. Reason: %s", basename(fpath), e)

                    err_msg = ""
                    if isinstance(e, HTTPError):
                        err_msg = f"\nReason: {e.response.json()['error']}"

                    inmain(idc.warning, f"Error analysing {basename(fpath)}.{err_msg}")
                finally:
                    inmain(hide_wait_box)
            else:
                inmain(idc.warning,
                       f"Please be advised that the largest size for processing a binary file is"
                       f" {state.config.LIMIT // (1024 ** 2)} MB.")

        f = UploadBinaryForm(state)

        if f.Show():
            symbols: dict = {"base_addr": get_imagebase()}

            functions = []
            for func_ea in idautils.Functions():
                functions.append({"name": IDAUtils.get_demangled_func_name(func_ea),
                                  "start_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_START),
                                  "end_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_END)})

            symbols["functions"] = functions

            inthread(bg_task, state.config.MODELS[f.iModel.value],
                     f.iTags.value.split(","), "PUBLIC" if f.iScope.value else "PRIVATE", f.iDebugFile.value)

        f.Free()


def check_analyze(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task() -> None:
            try:
                bid = state.config.get("binary_id", 0)

                res: Response = RE_status(fpath, bid)

                status = res.json()["status"]

                if bid:
                    inmain(state.config.database.update_analysis, bid, status)

                logger.info("Got binary analysis status: %s", status)
                Dialog.showInfo("Check Binary Analysis Status", f"Binary analysis status: {status}")
            except HTTPError as e:
                logger.error("Error getting binary analysis status: %s",
                             e.response.json().get("error",
                                                   "An unexpected error occurred. Sorry for the inconvenience."))

                Dialog.showError("Check Binary Analysis Status",
                                 """Error getting binary analysis status.\n\nPlease check:
    • You have downloaded your binary ID from the portal.
    • You have uploaded the current binary to the portal.""")

        inthread(bg_task)


def auto_analyze(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task() -> None:
            done, status = is_analysis_complete(state, fpath)
            if done:
                dialog = inmain(AutoAnalysisDialog, state, fpath)
                inmain(dialog.exec_)
            else:
                Dialog.showInfo("Auto Analysis",
                                f"Unable to fulfil your request at this time.\nBinary analysis status: {status}")

        inthread(bg_task)


def rename_function(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task() -> None:
            done, status = is_analysis_complete(state, fpath)
            if done:
                dialog = inmain(FunctionSimilarityDialog, state, fpath)
                inmain(dialog.exec_)
            else:
                Dialog.showInfo("Function Renaming",
                                f"Unable to fulfil your request at this time.\nBinary analysis status: {status}")

        inthread(bg_task)


def explain_function(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task(pseudo_code: str) -> None:
            if len(pseudo_code) > 0:
                try:
                    # Gets the programming language from the current binary
                    ret = run(f"rabin2 -I {fpath} | grep 'lang '", shell=True, capture_output=True)

                    res: Response = RE_explain(pseudo_code,
                                               ret.stdout.split(b' ')[
                                                   -1].strip().decode() if ret.returncode == 0 else None)

                    error = res.json().get("error", None)
                    if error:
                        logger.error("Error with function explanation: %s", error)
                        Dialog.showError("", f"Error getting function explanation: {error}")
                    else:
                        comment = f"RevEng.AI Autogenerated\n\n{res.json()['explanation']}"

                        logger.info(comment)
                        inmain(IDAUtils.set_comment, inmain(idc.here), comment)
                except HTTPError as e:
                    logger.error("Error with function explanation: %s", e)

                    error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
                    Dialog.showError("Function Explanation", f"Error getting function explanation: {error}")
            else:
                info = inmain(get_inf_structure)

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

    if is_condition_met(state, fpath):
        def bg_task() -> None:
            try:
                res: Response = RE_logs(fpath, console=False, binary_id=state.config.get("binary_id", 0))

                if res.json()["success"]:
                    filename = inmain(ask_file, 1, "*.log", "Output Filename:")

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

                error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
                Dialog.showError("Binary Analysis Logs", f"Unable to download binary analysis logs: {error}")

        inthread(bg_task)


def function_signature(state: RevEngState, func_addr: int = 0) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task(start_addr: int) -> None:
            try:
                if start_addr is not idc.BADADDR:
                    start_addr -= inmain(get_imagebase)

                    res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

                    for function in res.json()["functions"]:
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

                error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
                Dialog.showError("Binary Analysis Logs", f"Failed to obtain function argument details: {error}")

        inthread(bg_task, idc.get_func_attr(func_addr if func_addr > 0 else idc.here(), idc.FUNCATTR_START))


def analysis_history(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task() -> None:
            try:
                res: Response = RE_search(fpath)

                sha_256_hash = re_binary_id(fpath)

                results = list(filter(lambda binary: binary["sha_256_hash"] == sha_256_hash,
                                      res.json()["query_results"]))

                results.sort(key=lambda binary: datetime.fromisoformat(binary["creation"]).timestamp(), reverse=True)

                binaries = []
                today = date.today()

                for binary in results:
                    creation = datetime.fromisoformat(binary["creation"]).astimezone()

                    binaries.append((binary.get("binary_name"), str(binary["binary_id"]), binary["status"],
                                     creation.strftime("Today at %H:%M:%S")
                                     if creation.date() == today else
                                     creation.strftime("Yesterday at %H:%M:%S")
                                     if creation.date() == today - timedelta(days=1) else
                                     creation.strftime("%Y-%m-%d, %H:%M:%S"),))

                    inmain(state.config.database.add_analysis,
                           binary["sha_256_hash"], binary["binary_id"], binary["status"], binary["creation"])

                if len(binaries):
                    f = inmain(StatusForm, state, binaries)
                    inmain(f.Show)
                    inmain(f.Free)
                else:
                    logger.info("%s not yet analyzed", basename(fpath))
                    Dialog.showInfo("Binary Analysis History", f"{basename(fpath)} binary not yet analyzed.")
            except HTTPError as e:
                logger.error("Unable to obtain binary analysis history. %s", e)

                error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
                Dialog.showError("Binary Analysis History", f"Failed to obtain binary analysis history: {error}")

        inthread(bg_task)


def load_recent_analyses(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if state.config.is_valid():
        def bg_task() -> None:
            try:
                res: Response = RE_recent_analysis()

                for analysis in res.json()["analysis"]:
                    inmain(state.config.database.add_upload, analysis["binary_name"], analysis["sha_256_hash"])
                    inmain(state.config.database.add_analysis, analysis["sha_256_hash"],
                           analysis["binary_id"], analysis["status"], analysis["creation"], analysis["model_name"])

                params = [re_binary_id(fpath)]

                binaries = list(filter(lambda binary: binary["sha_256_hash"] == params[0],
                                       RE_search(fpath).json()["query_results"]))

                if len(binaries) == 0:
                    state.config.set("binary_id", None)
                else:
                    params += [binary["binary_id"] for binary in binaries]

                    inmain(state.config.database.execute_sql,
                           f"DELETE FROM analysis WHERE sha_256_hash = ? AND binary_id NOT IN "
                           f"({('?, ' * len(binaries))[:-2]})", tuple(params))

                    state.config.set("binary_id", inmain(state.config.database.get_last_analysis, params[0]))

                    done, _ = is_analysis_complete(state, fpath)
                    if done:
                        inmain(sync_functions_name, state, fpath)
            except RequestException as e:
                logger.error("Error getting recent analyses: %s", e)

        inthread(bg_task)


def sync_functions_name(state: RevEngState, fpath: str) -> None:
    if state.config.is_valid() and fpath and isfile(fpath):
        def bg_task() -> None:
            try:
                res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

                data = None if state.config.auto_sync else []
                for function in res.json()["functions"]:
                    func_name = next((func["name"] for func in functions
                                      if function["function_vaddr"] == func["start_addr"]
                                      and not func["name"].startswith("sub_")), None)

                    if func_name and func_name != function["function_name"]:
                        if data is not None:
                            function["function_name"] = func_name
                            function["function_vaddr"] += base_addr

                            data.append(function)
                        else:
                            try:
                                RE_functions_rename(function["function_id"], func_name)
                            except HTTPError as e:
                                logger.warning("Failed to sync functionId %d. %s",
                                               function["function_id"], e.response.reason)

                if data and len(data):
                    dialog = inmain(SyncFunctionsDialog, state, fpath, data)
                    inmain(dialog.exec_)
            except RequestException as e:
                logger.error("Error syncing functions: %s", e)

        functions = []
        base_addr = get_imagebase()

        for func_ea in idautils.Functions():
            functions.append({"name": IDAUtils.get_demangled_func_name(func_ea),
                              "start_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_START) - base_addr})

        inthread(bg_task)


def function_breakdown(state: RevEngState, function_id: int = 0) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task(func_ea: int, func_id: int = 0) -> None:
            func_name = inmain(IDAUtils.get_demangled_func_name, func_ea)

            if not func_id:
                done, status = is_analysis_complete(state, fpath)
                if not done:
                    Dialog.showInfo("Function Breakdown",
                                    f"Unable to fulfil your request at this time.\nBinary analysis status: {status}")
                    return

                func_ea -= inmain(get_imagebase)

                try:
                    inmain(show_wait_box,
                           f"HIDECANCEL\nGetting information on the function breakdown of {func_name}…")

                    res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

                    func_id = next((function["function_id"] for function in res.json()["functions"]
                                    if function["function_vaddr"] == func_ea), 0)
                except HTTPError as e:
                    logger.error("Error getting function list: %s",
                                 e.response.json().get("error",
                                                       "An unexpected error occurred. Sorry for the inconvenience."))
                except RequestException as e:
                    logger.error("An unexpected error has occurred. %s", e)
                finally:
                    inmain(hide_wait_box)

            if func_id:
                logger.info("Redirection to the WEB browser to display the function breakdown ID %d | %s",
                            func_id, func_name)

                from webbrowser import open_new_tab

                open_new_tab(f"{state.config.PORTAL}/function/{func_id}")

        inthread(bg_task, idc.get_func_attr(idc.here(), idc.FUNCATTR_START), function_id)


def is_analysis_complete(state: RevEngState, fpath: str) -> tuple[bool, str]:
    try:
        bid = state.config.get("binary_id", 0)

        res: Response = RE_status(fpath, bid)

        status = res.json()["status"]

        if bid:
            inmain(state.config.database.update_analysis, bid, status)

        return status == "Complete", status
    except HTTPError as e:
        error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
        if "invalid" in error.lower():
            upload_binary(state)

        logger.error("Error getting binary analysis status: %s", error)
        return False, "Processing"


def is_condition_met(state: RevEngState, fpath: str) -> bool:
    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning("No input file provided.")
    else:
        return True
    return False


def is_file_supported(state: RevEngState, fpath: str) -> bool:
    try:
        file_format, isa_format = file_type(fpath)

        logger.info("Underlying binary: %s -> format: %s target: %s", fpath, file_format, isa_format)

        if any(file_format == fmt for fmt in state.config.OPTIONS.get("file_options", [])) and \
                any(isa_format == fmt for fmt in state.config.OPTIONS.get("isa_options", [])):
            return True
    except Exception:
        pass

    idc.warning(f"{basename(fpath)} file format is not currently supported by RevEng.AI")
    return False


def about(_) -> None:
    f = AboutForm()
    f.Show()
    f.Free()


def update(_) -> None:
    try:
        res: Response = get("https://github.com/RevEngAI/reai-ida/releases/latest", timeout=30)

        res.raise_for_status()

        version_stable = res.url.split("/")[-1]

        f = UpdateForm("Good, you are already using the latest stable version!"
                       if version_stable == __version__ else
                       f"Kindly download the latest stable version {version_stable}.")

        f.Show()
        f.Free()
    except HTTPError as e:
        logger.warning("RevEng.AI Toolkit failed to connect to GitHub to check for the latest plugin update. %s",
                       e)
        Dialog.showInfo("Check for Update",
                        "RevEng.AI Toolkit has failed to connect to the internet (Github). Try again later.")
