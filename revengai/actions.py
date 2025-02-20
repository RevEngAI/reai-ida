# -*- coding: utf-8 -*-
import logging
from time import sleep

import idc
import ida_funcs
import ida_typeinf
import ida_bytes
from idautils import Functions
from idaapi import ask_file, ask_buttons, get_imagebase, get_inf_structure, open_url, \
    retrieve_input_file_size, retrieve_input_file_sha256, show_wait_box, hide_wait_box, ASKBTN_YES, \
    simplecustviewer_t, get_screen_ea, execute_sync, MFF_FAST

from libbs.artifacts import Function
from subprocess import run, SubprocessError
from threading import Timer
from concurrent.futures import ThreadPoolExecutor

from requests import get, HTTPError, Response, RequestException
from os.path import basename, isfile
from datetime import date, datetime, timedelta

from reait.api import RE_upload, RE_analyse, RE_status, RE_logs, RE_analyze_functions, file_type, RE_functions_rename_batch, RE_analysis_id, RE_generate_data_types, RE_list_data_types, RE_poll_ai_decompilation, RE_begin_ai_decompilation

from revengai import __version__
from revengai.api import RE_explain, RE_functions_dump, RE_search, RE_recent_analysis, RE_generate_summaries
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
                                         tags=tags, symbols=symbols,
                                         duplicate=state.project_cfg.get("duplicate_analysis"))

                        analysis = res.json()

                        state.config.set("binary_id", analysis["binary_id"])

                        inmain(state.config.database.add_analysis,
                               sha_256_hash, analysis["binary_id"], analysis["success"])

                        logger.info("Binary analysis %s for: %s",
                                    "succeed" if analysis["success"] else "failed", basename(fpath))

                        # Periodically check the status of the uploaded binary
                        periodic_check(fpath, analysis["binary_id"])
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
            for func_ea in Functions():
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
                    if status in ("Queued", "Processing",):
                        periodic_check(fpath, bid)

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

def decompile_function_notes(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()
    if not is_condition_met(state, fpath):
        return

    base_addr = get_imagebase()
    
    # Prepare IDA functions
    ida_functions = [
        {
            "name": IDAUtils.get_demangled_func_name(func_ea),
            "start_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_START) - base_addr,
            'loc': idc.get_func_attr(func_ea, idc.FUNCATTR_START)
        }
        for func_ea in Functions()
    ]

    print("Processing Functions")
    print("There are %s functions to process" % len(ida_functions))
    print("Submiting functions to the server for processing")

    # Analyze functions in background
    def bg_task():
        try:
            res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))
            return res.json()["functions"]
        except HTTPError as e:
            logger.error("Unable to obtain function argument details. %s", e)
            error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
            Dialog.showError("Function Signature", f"Failed to obtain function argument details: {error}")
            return []

    with ThreadPoolExecutor() as executor:
        future = executor.submit(bg_task)

    print("Please Wait...")
    analyzed_functions = future.result()

    # Prepare function details
    function_ids = [func["function_id"] for func in analyzed_functions]
    function_details = {
        int(func["function_vaddr"]): func["function_id"]
        for func in analyzed_functions
    }

    """
    Removed until function submission has been upgraded to batch.
    # Submit functions for code generation
    RE_process_function(function_ids)
    """

    # Get function dumps
    res: Response = RE_functions_dump(function_ids)
    function_dumps = {
        func_dump['function_id']: func_dump['psuedo_c']
        for func_dump in res.json()["functions"]
    }

    # Set function comments
    for ida_func in ida_functions:
        function_id = function_details.get(ida_func['start_addr'])
        if function_id:
            psuedo_c = function_dumps.get(function_id)
            if psuedo_c:
                idc.set_func_cmt(ida_func['loc'], psuedo_c, 1)

    print("Done")

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

def push_function_names(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()
    if is_condition_met(state, fpath):
        
        ida_functions = []
        base_addr = get_imagebase()

        for func_ea in Functions():
            ida_functions.append({"name": IDAUtils.get_demangled_func_name(func_ea),
                              "start_addr": idc.get_func_attr(func_ea, idc.FUNCATTR_START) - base_addr})

        def bg_task() -> None:  
            try:
                function_ids = []
                res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))
              
                for function in res.json()["functions"]:
                    function_ids.append({"function_id":function["function_id"],"function_vaddr":int(function["function_vaddr"]),"function_name":function["function_name"]})
                    
            except HTTPError as e:
                logger.error("Unable to obtain function argument details. %s", e)

                error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
                Dialog.showError("Function Signature", f"Failed to obtain function argument details: {error}")
            try:
                function_remap = {}
                for ida_func in ida_functions:
                    for func in function_ids:
                        if func['function_vaddr'] == ida_func['start_addr'] and not ida_func['name'].startswith("sub_"):
                            function_remap[func['function_id']] = ida_func['name']
                
                res: Response = RE_functions_rename_batch(function_remap)
                if res.json()["success"]:
                    logger.info("Function names pushed successfully")
                else:
                    logger.error("Error pushing function names")
            except HTTPError as e:
                logger.error("Unable to obtain function argument details. %s", e)

                error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
                Dialog.showError("Function Signature", f"Failed to obtain function argument details: {error}")
            
        inthread(bg_task)

def explain_function(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task(pseudo_code: str) -> None:
            if pseudo_code and len(pseudo_code) > 0:
                try:
                    language = None
                    try:
                        # Gets the programming language from the current binary
                        ret = run(f"rabin2 -I {fpath} | grep 'lang '", shell=True, capture_output=True, timeout=5)

                        if ret.returncode == 0:
                            language = ret.stdout.split(b' ')[-1].strip().decode()
                    except SubprocessError as e:
                        logger.error("Failed to get the programming language. Reason: %s", e)

                    res: Response = RE_explain(pseudo_code, language)

                    error = res.json().get("error", None)
                    if error:
                        logger.error("Error with function explanation: %s", error)
                        Dialog.showError("", f"Error getting function explanation: {error}")
                    else:
                        comment = f"RevEng.AI Auto-generated Explanation:\n\n{res.json()['explanation']}"

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


def function_signature(state: RevEngState, func_addr: int = 0, func_id: int = 0) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task(func_ea: int) -> None:
            try:
                function_ids = []
                if func_id:
                    function_ids.append(func_id)
                else:
                    res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

                    start_addr = func_ea - inmain(get_imagebase)
                    for function in res.json()["functions"]:
                        if function["function_vaddr"] == start_addr:
                            function_ids.append(function["function_id"])

                res = RE_functions_dump(function_ids)

                for function in res.json()["functions"]:
                    if any(function["function_id"] == function_id for function_id in function_ids):
                        r_type = "void" if function["return_type"] == "undefined" else function["return_type"]
                        params = ", ".join([f"{param['d_type'].replace('typedef ', '')} {param['name']}"
                                            for param in function["params"]])

                        func_sig = f"{r_type} {inmain(idc.get_func_name, func_ea)}({params})"

                        if inmain(idc.SetType, func_ea, func_sig):
                            IDAUtils.refresh_pseudocode_view(func_ea)

                            logger.info("New function declaration '%s' set at address 0x%X", func_sig, func_ea)
                        else:
                            logger.warning("Failed to set function declaration '%s' at address 0x%X", func_sig, func_ea)
                            Dialog.showInfo("Function Declaration",
                                            f"Failed to update the function declaration with:\n{func_sig}")
            except HTTPError as e:
                logger.error("Unable to obtain function argument details. %s", e)

                error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
                Dialog.showError("Function Signature", f"Failed to obtain function argument details: {error}")

        inthread(bg_task, idc.get_func_attr(func_addr if func_addr > 0 else idc.here(), idc.FUNCATTR_START))


def analysis_history(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task() -> None:
            try:
                res: Response = RE_search(fpath)

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
                                     creation.strftime("%Y-%m-%d, %H:%M:%S"),
                                     binary["model_name"],))

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

        sha_256_hash = retrieve_input_file_sha256().hex()

        inthread(bg_task)


def load_recent_analyses(state: RevEngState) -> None:
    if state.config.is_valid():
        def bg_task() -> None:
            try:
                res: Response = RE_recent_analysis()

                for analysis in res.json()["analysis"]:
                    inmain(state.config.database.add_upload, analysis["binary_name"], analysis["sha_256_hash"])
                    inmain(state.config.database.add_analysis, analysis["sha_256_hash"],
                           analysis["binary_id"], analysis["status"], analysis["creation"], analysis["model_name"])

                params = [sha_256_hash]

                binaries = list(filter(lambda binary: binary["sha_256_hash"] == sha_256_hash,
                                       RE_search(fpath).json()["query_results"]))

                if len(binaries) == 0:
                    state.config.set("binary_id", None)
                else:
                    params += [binary["binary_id"] for binary in binaries]

                    inmain(state.config.database.execute_sql,
                           f"DELETE FROM analysis WHERE sha_256_hash = ? AND binary_id NOT IN "
                           f"({('?, ' * len(binaries))[:-2]})", tuple(params))

                    state.config.set("binary_id", inmain(state.config.database.get_last_analysis, sha_256_hash))

                    if state.project_cfg.get("auto_sync"):
                        done, _ = is_analysis_complete(state, fpath)
                        if done:
                            inmain(sync_functions_name, state, fpath)
            except RequestException as e:
                logger.error("Error getting recent analyses: %s", e)

        fpath = idc.get_input_file_path()
        sha_256_hash = retrieve_input_file_sha256().hex()

        inthread(bg_task)


def sync_functions_name(state: RevEngState, fpath: str) -> None:
    if state.config.is_valid() and fpath and isfile(fpath):
        def bg_task() -> None:
            try:
                res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

                data = []
                for function in res.json()["functions"]:
                    func_name = next((func["name"] for func in functions
                                      if function["function_vaddr"] == func["start_addr"]
                                      and not func["name"].startswith("sub_")), None)

                    if func_name and func_name != function["function_name"]:
                        function["function_vaddr"] += base_addr
                        function["function_display"] = f"{func_name}  ➡  {function['function_name']}"

                        data.append(function)

                if len(data):
                    dialog = inmain(SyncFunctionsDialog, state, fpath, data)
                    inmain(dialog.exec_)
            except RequestException as e:
                logger.error("Error syncing functions: %s", e)

        functions = []
        base_addr = get_imagebase()

        for func_ea in Functions():
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

                inmain(open_url, f"{state.config.PORTAL}/function/{func_id}")

        inthread(bg_task, idc.get_func_attr(idc.here(), idc.FUNCATTR_START), function_id)


def generate_function_data_types(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):
        def bg_task() -> None:
            done, status = is_analysis_complete(state, fpath)
            if done:
                    res: Response = RE_analysis_id(fpath, state.config.get("binary_id", 0))
                    analysis_id = res.json()["analysis_id"]
                    function_ids = []
                    res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))
                    for function in res.json()["functions"]:
                        function_ids.append(function["function_id"])
                    res: Response = RE_generate_data_types(analysis_id,function_ids)
            else:
                Dialog.showInfo("Function Types",
                                f"Unable to fulfil your request at this time.\nBinary analysis status: {status}")

        inthread(bg_task)

def list_function_data_types(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()
    
    if is_condition_met(state, fpath):
        
        base_addr = get_imagebase()

        try:
            res: Response = RE_analysis_id(fpath, state.config.get("binary_id", 0))
            analysis_id = res.json()["analysis_id"]
            function_ids = []
            res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

            for function in res.json()["functions"]:
                function_ids.append(function["function_id"])
                
        except HTTPError as e:
            logger.error("Unable to obtain function Ids. %s", e)

            error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
            Dialog.showError("Function Signature", f"Failed to obtain function argument details: {error}")
        try:
            res: Response = RE_list_data_types(analysis_id,function_ids)
            res = res.json()
            if not (res.get("status") and res.get("data") and "items" in res["data"]):
                print("No function data found in response")
                return

            items = res["data"]["items"]
            for item in items:
                try:
                    # Extract function type information
                    func_types = item.get('data_types', {}).get('func_types', {})
                    if not func_types:
                        continue

                    # Get function details
                    func_addr = func_types.get('addr')
                    if func_addr is None:
                        continue
                    
                    func_addr = func_addr + base_addr
                    func_name = func_types.get('header', {}).get('name', f'unnamed_func_{hex(func_addr)}')
                    func_type = func_types.get('type', 'void')
                    
                    # Validate segment
                    if not idc.get_segm_name(func_addr):
                        logger.warning(f"Address {hex(func_addr)} is outside valid segments")
                        continue

                    # Create or get function
                    func = ida_funcs.get_func(func_addr)
                    if not func:
                        # Undefine existing data at address
                        ida_bytes.del_items(func_addr, ida_bytes.DELIT_SIMPLE, 0)
                        
                        # Create new function
                        if not ida_funcs.add_func(func_addr):
                            logger.error(f"Failed to create function at {hex(func_addr)}")
                            continue
                        func = ida_funcs.get_func(func_addr)

                    # Create function type information
                    try:
                        func_type_data = ida_typeinf.func_type_data_t()
                        
                        # Set return type
                        ret_tinfo = ida_typeinf.tinfo_t()
                        if func_type == "void":
                            ret_tinfo.create_simple_type(ida_typeinf.BTF_VOID)
                        else:
                            # Handle other return types - can be expanded
                            ret_tinfo.create_simple_type(ida_typeinf.BTF_UINT)
                            
                        func_type_data.rettype = ret_tinfo

                        # Process arguments
                        args = func_types.get('header', {}).get('args', {})
                        for arg_offset, arg_info in args.items():
                            arg_type = arg_info.get('type', 'void *')
                            arg_name = arg_info.get('name', f'param_{arg_offset}')
                            
                            # Create argument type info
                            arg_tinfo = ida_typeinf.tinfo_t()
                            arg_tinfo.create_simple_type(ida_typeinf.BTF_UINT)
                            
                            # Create funcarg_t object
                            arg = ida_typeinf.funcarg_t()
                            arg.name = arg_name
                            arg.type = arg_tinfo
                            
                            # Add argument to function type
                            func_type_data.push_back(arg)

                        # Create final type information
                        final_tinfo = ida_typeinf.tinfo_t()
                        final_tinfo.create_func(func_type_data)
                        ida_typeinf.apply_tinfo(func_addr, final_tinfo, ida_typeinf.TINFO_DEFINITE)
                        # Apply type information
                        """
                        if ida_typeinf.apply_tinfo(func_addr, final_tinfo, ida_typeinf.TINFO_DEFINITE):
                            idc.set_name(func_addr, func_name, idc.SN_NOWARN)
                            logger.info(f"Successfully mapped {func_name} at {hex(func_addr)}")
                        else:
                            logger.error(f"Failed to apply type for {func_name}")
                        """
                    except Exception as e:
                        logger.error(f"Error creating type info for {func_name}: {str(e)}")
                        continue

                except Exception as e:
                    logger.error(f"Error processing function: {str(e)}")

                    
        except Exception as e:
            print(f"Error processing function types: {e}")
            
def ai_decompile(state: RevEngState) -> None:
    def bg_task(start_addr: int, callback) -> None:  
        try:

            res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))
            for function in res.json()["functions"]:
                if function['function_vaddr'] == start_addr:
                    data_status = ""
                    while 'success' not in data_status:
                        res: Response = RE_poll_ai_decompilation(function['function_id'])
                        req = res.json()
                        data_status = req['data']['status']
                        if 'uninitialised' in data_status:
                            res: Response = RE_begin_ai_decompilation(function['function_id'])
                        decomp_data = req['data']['decompilation']
                        sleep(5)
                    print (decomp_data)
                    execute_sync(lambda: callback(decomp_data), MFF_FAST)
        
        except HTTPError as e:
            logger.error("Unable to obtain function argument details. %s", e)
            error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
            Dialog.showError("Function Signature", f"Failed to obtain function argument details: {error}")
            return None
        
    def handle_ai_decomp(decomp_data):
        if decomp_data:
            try:
                sv.ClearLines()
                lines = str(decomp_data).split("\n")
                for line in lines:
                    sv.AddLine(line)
                sv.Refresh()
            except Exception as e:
                print(f"Error: {e}")

    fpath = idc.get_input_file_path()
    if is_condition_met(state, fpath):
        ea = get_screen_ea()
        func_ea = ida_funcs.get_func(ea)
        if func_ea:
            func_name = IDAUtils.get_demangled_func_name(func_ea.start_ea)
            start_addr = func_ea.start_ea
            try:
                # Create a custom viewer subview for the decompiled code4
                sv = simplecustviewer_t()
                if sv.Create(f"AI Decompilation of {func_name}"):
                    sv.ClearLines()
                    sv.AddLine("Please wait while the function is decompiled...")
                    sv.Show()
            except Exception as e:
                print(f"Error: {e}")
            inthread(bg_task, start_addr, handle_ai_decomp)
        
def generate_summaries(state: RevEngState, function_id: int = 0) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath) and \
            ASKBTN_YES == ask_buttons("Generate", "Cancel", "", ASKBTN_YES,
                                      "HIDECANCEL\nWould you like to generate summaries?\n\n"
                                      "The cost of this operation is estimated to be 0.045 credits,\n"
                                      "and will generate summaries for each node in the flow.\n\n"
                                      "This action is irreversible and cannot be undone."):
        def bg_task(func_ea: int, func_id: int = 0) -> None:
            func_name = inmain(IDAUtils.get_demangled_func_name, func_ea)

            if not func_id:
                done, status = is_analysis_complete(state, fpath)
                if not done:
                    Dialog.showInfo("Generate Summaries",
                                    f"Unable to fulfil your request at this time.\nBinary analysis status: {status}")
                    return

                func_ea -= inmain(get_imagebase)

                try:
                    res: Response = RE_analyze_functions(fpath, state.config.get("binary_id", 0))

                    func_id = next((function["function_id"] for function in res.json()["functions"]
                                    if function["function_vaddr"] == func_ea), 0)
                except HTTPError as e:
                    logger.error("Error getting function list: %s",
                                 e.response.json().get("error",
                                                       "An unexpected error occurred. Sorry for the inconvenience."))
                except RequestException as e:
                    logger.error("An unexpected error has occurred. %s", e)

            if func_id:
                logger.info("Generates block summaries for function ID %d | %s", func_id, func_name)

                try:
                    inmain(show_wait_box, f"HIDECANCEL\nGenerating block summaries for {func_name}…")

                    res: Response = RE_generate_summaries(func_id)

                    #TODO Need to process the response
                except HTTPError as e:
                    logger.error("Error generating block summaries: %s",
                                 e.response.json().get("error", "An unexpected error occurred."))
                finally:
                    inmain(hide_wait_box)

        inthread(bg_task, idc.get_func_attr(idc.here(), idc.FUNCATTR_START), function_id)


def is_analysis_complete(state: RevEngState, fpath: str) -> tuple[bool, str]:
    try:
        bid = state.config.get("binary_id", 0)

        res: Response = RE_status(fpath, bid)

        status = res.json()["status"]

        if bid:
            if status in ("Queued", "Processing",):
                periodic_check(fpath, bid)

            inmain(state.config.database.update_analysis, bid, status)

        return status == "Complete", status
    except HTTPError as e:
        error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")

        # if any(word in error.lower()for word in ("invalid", "denied",)):
        #     inmain(upload_binary, state)

        logger.error("Error getting binary analysis status: %s", error)
        return False, error if any(word in error.lower()for word in ("invalid", "denied",)) else "Processing"


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

        logger.info("Underlying binary: %s -> format: %s, target: %s", fpath, file_format, isa_format)

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
    except RequestException as e:
        logger.warning("RevEng.AI Toolkit failed to connect to GitHub to check for the latest plugin update. %s",
                       e)
        Dialog.showInfo("Check for Update",
                        "RevEng.AI Toolkit has failed to connect to the internet (Github). Try again later.")


def periodic_check(fpath: str, binary_id: int) -> None:
    def _worker(bid: int, interval: float = 60):
        try:
            status = RE_status(fpath, bid).json()["status"]

            if status in ("Queued", "Processing",):
                if inmain(idc.get_input_file_path) == fpath:
                    Timer(interval, _worker, args=(bid, interval,)).start()
                    logger.info("Scheduling binary analysis status for: %s [%d]", basename(fpath), bid)
        except RequestException as ex:
            logger.error("Error getting binary analysis status. Reason: %s", ex)

    Timer(30, _worker, args=(binary_id,)).start()
    logger.info("Scheduling binary analysis status for: %s [%d]", basename(fpath), binary_id)


def toolbar(state: RevEngState) -> None:
    """
    Workaround to show RevEng.AI logo in toolbar to create menu bar when clicked
    """
    from revengai.ida_ui import RevEngConfigForm_t

    form = RevEngConfigForm_t(state)
    form.register_actions(False)
    del form
