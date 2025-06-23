import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta
from os.path import basename, isfile
from threading import Timer
from time import sleep
import idc
from idautils import Functions
import idaapi
import ida_funcs
from requests import get, HTTPError, Response, RequestException
from revengai.misc.datatypes import (
    wait_box_decorator_noclazz,
    import_data_types,
)
from revengai.ai_decompilation_view import AICodeViewer

import traceback as tb

from reait.api import (
    RE_upload,
    RE_analyse,
    RE_status,
    RE_logs,
    RE_analyze_functions,
    file_type,
    RE_functions_rename_batch,
    RE_analysis_lookup,
    RE_poll_ai_decompilation,
    RE_begin_ai_decompilation,
    RE_functions_data_types,
    RE_functions_list,
    RE_users_me,
    RE_recent_analysis_v2,
    RE_models,
    RE_get_analysis_id_from_binary_id,
    RE_get_functions_from_analysis, 
)

from revengai import __version__
from revengai.api import (
    RE_functions_dump,
    RE_search,
    RE_generate_summaries,
)
from revengai.features.auto_analyze import AutoAnalysisDialog
from revengai.features.function_similarity import FunctionSimilarityDialog
from revengai.features.sync_functions import SyncFunctionsDialog
from revengai.features.auto_unstrip import AutoUnstrip
from revengai.gui.dialog import (
    Dialog,
    StatusForm,
    UploadBinaryForm,
    AboutForm,
    UpdateForm,
)
from revengai.manager import RevEngState
from revengai.misc.qtutils import inthread, inmain
from revengai.misc.utils import IDAUtils
from revengai.wizard.wizard import RevEngSetupWizard

from revengai.features.sync_functions import SyncOp
from revengai.models import CheckableItem

from revengai.helpers.file import file_type_ida

from idaapi import ASKBTN_YES, ask_buttons

logger = logging.getLogger("REAI")

version = float(idaapi.get_kernel_version())
if version < 9.0:
    def is_32bit() -> bool:
        info: idaapi.idainfo = idaapi.get_inf_structure()
        return info.is_32bit()

    def is_64bit() -> bool:
        info: idaapi.idainfo = idaapi.get_inf_structure()
        return info.is_64bit()
else:
    def is_32bit() -> bool:
        return idaapi.inf_is_32bit_exactly()

    def is_64bit() -> bool:
        return idaapi.inf_is_64bit()


def setup_wizard(state: RevEngState) -> None:
    RevEngSetupWizard(state).exec_()


def upload_binary(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath) and is_file_supported(state, fpath):

        def bg_task(
            model: str,
            tags: list = None,
            scope: str = "PRIVATE",
            debug_fpath: str = None,
        ) -> None:
            file_size = inmain(idaapi.retrieve_input_file_size)

            if state.config.LIMIT > file_size:
                try:
                    inmain(
                        idaapi.show_wait_box,
                        "HIDECANCEL\nUploading binary for analysis…",
                    )

                    res: Response = RE_upload(fpath)
                    upload = res.json()

                    logger.info(
                        "Upload ended for: %s. %s",
                        basename(fpath),
                        upload["message"],
                    )

                    if upload["success"]:
                        sha_256_hash = upload["sha_256_hash"]

                        inmain(
                            state.config.database.add_upload,
                            fpath,
                            sha_256_hash,
                        )

                        res = RE_analyse(
                            fpath=fpath,
                            binary_scope=scope,
                            debug_fpath=debug_fpath,
                            model_name=model,
                            tags=tags,
                            symbols=symbols,

                            duplicate=state.project_cfg.get(
                                "duplicate_analysis"
                            ),
                            dynamic_execution=False,
                            # NOTE: disable all other analyses options
                            skip_scraping=True,
                            skip_sbom=True,
                            skip_capabilities=True,
                            advanced_analysis=False,
                            skip_cves=True
                        )

                        analysis = res.json()

                        res = RE_analysis_lookup(analysis["binary_id"])

                        analysis_info = res.json()

                        state.config.set(
                            "binary_id",
                            analysis["binary_id"]
                        )
                        state.config.set(
                            "analysis_id",
                            analysis_info["analysis_id"]
                        )

                        inmain(
                            state.config.database.add_analysis,
                            sha_256_hash,
                            analysis["binary_id"],
                            analysis["success"],
                        )

                        logger.info(
                            "Binary analysis %s for: %s",
                            "succeed" if analysis["success"] else "failed",
                            basename(fpath),
                        )

                        # Periodically check the status of the uploaded binary
                        periodic_check(state, fpath, analysis["binary_id"])
                except HTTPError as e:
                    resp = e.response.json()
                    errors = resp.get("errors", [])
                    err_msg = (
                        errors[0]["msg"]
                        if len(errors) > 0
                        else "An unexpected error occurred. Sorry for the"
                        " inconvenience."
                    )

                    logger.error(
                        "Error analysing %s: %s",
                        basename(fpath),
                        err_msg,
                    )

                    inmain(
                        idc.warning,
                        f"Error analysing {basename(fpath)}.{err_msg}",
                    )
                finally:
                    inmain(idaapi.hide_wait_box)
            else:
                inmain(
                    idc.warning,
                    f"Please be advised that the largest size for processing a"
                    " binary file is"
                    f" {state.config.LIMIT // (1024 ** 2)} MB.",
                )

        f = UploadBinaryForm(state)

        if f.Show():
            symbols: dict = {"base_addr": idaapi.get_imagebase()}

            functions = []
            for func_ea in Functions():
                functions.append(
                    {
                        "name": IDAUtils.get_demangled_func_name(func_ea),
                        "start_addr": idc.get_func_attr(
                            func_ea,
                            idc.FUNCATTR_START
                        ),
                        "end_addr": idc.get_func_attr(
                            func_ea,
                            idc.FUNCATTR_END
                        ),
                    }
                )

            symbols["functions"] = functions

            inthread(
                bg_task,
                state.config.MODELS[f.iModel.value],
                f.iTags.value.split(","),
                "PUBLIC" if f.iScope.value else "PRIVATE",
                f.iDebugFile.value,
            )

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
                    if status in (
                        "Queued",
                        "Processing",
                    ):
                        periodic_check(state, fpath, bid)

                    inmain(state.config.database.update_analysis, bid, status)

                logger.info("Got binary analysis status: %s", status)
                Dialog.showInfo(
                    "Check Binary Analysis Status",
                    f"Binary analysis status: {status}",
                )
            except HTTPError as e:
                logger.error(
                    "Error getting binary analysis status: %s",
                    e.response.json().get(
                        "error",
                        "An unexpected error occurred. Sorry for the"
                        " inconvenience.",
                    ),
                )

                Dialog.showError(
                    "Check Binary Analysis Status",
                    """Error getting binary analysis status.\n\nPlease check:
    • You have downloaded your binary ID from the portal.
    • You have uploaded the current binary to the portal.""",
                )

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
                Dialog.showInfo(
                    "Analyse Binary",
                    "Unable to fulfil your request at this time.\nBinary"
                    f" analysis status: {status}",
                )

        inthread(bg_task)


def decompile_function_notes(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()
    if not is_condition_met(state, fpath):
        return

    base_addr = idaapi.get_imagebase()

    # Prepare IDA functions
    ida_functions = [
        {
            "name": IDAUtils.get_demangled_func_name(func_ea),
            "start_addr": idc.get_func_attr(
                func_ea,
                idc.FUNCATTR_START
            ) - base_addr,
            "loc": idc.get_func_attr(func_ea, idc.FUNCATTR_START),
        }
        for func_ea in Functions()
    ]

    print("Processing Functions")
    print("There are %s functions to process" % len(ida_functions))
    print("Submiting functions to the server for processing")

    # Analyze functions in background
    def bg_task():
        try:
            res: Response = RE_analyze_functions(
                fpath, state.config.get("binary_id", 0)
            )
            return res.json()["functions"]
        except HTTPError as e:
            logger.error("Unable to obtain function argument details. %s", e)
            error = e.response.json().get(
                "error",
                "An unexpected error occurred. Sorry for the inconvenience.",
            )
            Dialog.showError(
                "Function Signature",
                f"Failed to obtain function argument details: {error}",
            )
            return []

    with ThreadPoolExecutor() as executor:
        future = executor.submit(bg_task)

    print("Please Wait...")
    analyzed_functions = future.result()

    # Prepare function details
    function_ids = [func["function_id"] for func in analyzed_functions]
    function_details = {
        int(func["function_vaddr"]): func["function_id"] for func in
        analyzed_functions
    }

    """
    Removed until function submission has been upgraded to batch.
    # Submit functions for code generation
    RE_process_function(function_ids)
    """

    # Get function dumps
    res: Response = RE_functions_dump(function_ids)
    function_dumps = {
        func_dump["function_id"]: func_dump["psuedo_c"]
        for func_dump in res.json()["functions"]
    }

    # Set function comments
    for ida_func in ida_functions:
        function_id = function_details.get(ida_func["start_addr"])
        if function_id:
            psuedo_c = function_dumps.get(function_id)
            if psuedo_c:
                idc.set_func_cmt(ida_func["loc"], psuedo_c, 1)

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
                Dialog.showInfo(
                    "Function Renaming",
                    "Unable to fulfil your request at this time.\nBinary"
                    f" analysis status: {status}",
                )

        inthread(bg_task)


def push_function_names(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()
    if is_condition_met(state, fpath):

        ida_functions = []
        base_addr = idaapi.get_imagebase()

        for func_ea in Functions():
            ida_functions.append(
                {
                    "name": IDAUtils.get_func_name(func_ea),
                    "start_addr": idc.get_func_attr(
                        func_ea,
                        idc.FUNCATTR_START
                    ) - base_addr,
                }
            )

        def bg_task() -> None:
            try:
                function_ids = []
                res: Response = RE_analyze_functions(
                    fpath, state.config.get("binary_id", 0)
                )

                for function in res.json()["functions"]:
                    function_ids.append(
                        {
                            "function_id": function["function_id"],
                            "function_vaddr": int(function["function_vaddr"]),
                            "function_name": function["function_name"],
                        }
                    )

            except HTTPError as e:
                logger.error(
                    "Unable to obtain function argument details. %s",
                    e
                )

                error = e.response.json().get(
                    "error",
                    "An unexpected error occurred. Sorry for the "
                    "inconvenience.",
                )
                Dialog.showError(
                    "Function Signature",
                    f"Failed to obtain function argument details: {error}",
                )
            try:
                function_remap = {}
                for ida_func in ida_functions:
                    for func in function_ids:
                        if func["function_vaddr"] == ida_func[
                            "start_addr"
                        ] and not ida_func["name"].startswith("sub_"):
                            function_remap[func["function_id"]] = \
                                ida_func["name"]

                res: Response = RE_functions_rename_batch(function_remap)
                if res.json()["success"]:
                    logger.info("Function names pushed successfully")
                else:
                    logger.error("Error pushing function names")
            except HTTPError as e:
                logger.error(
                    "Unable to obtain function argument details. %s",
                    e
                )

                error = e.response.json().get(
                    "error",
                    "An unexpected error occurred. Sorry for the"
                    " inconvenience.",
                )
                Dialog.showError(
                    "Function Signature",
                    f"Failed to obtain function argument details: {error}",
                )

        inthread(bg_task)


def download_logs(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):

        def bg_task() -> None:
            try:
                res: Response = RE_logs(
                    fpath,
                    console=False,
                    binary_id=state.config.get("binary_id", 0),
                )

                if res.json()["success"]:
                    filename = inmain(
                        idaapi.ask_file, 1,
                        "*.log",
                        "Output Filename:"
                    )

                    if filename:
                        with open(filename, "w") as fd:
                            fd.write(res.json()["logs"])
                    else:
                        logger.warning(
                            "No output directory provided to export logs to"
                        )
                        inmain(
                            idc.warning,
                            "No output directory provided to export logs to.",
                        )
                else:
                    logger.warning(
                        "No binary analysis logs found for: %s",
                        basename(fpath),
                    )
                    inmain(
                        idc.warning,
                        "No binary analysis logs found for:"
                        f" {basename(fpath)}.",
                    )
            except HTTPError as e:
                logger.error(
                    "Unable to download binary analysis logs for: %s."
                    " Reason: %s",
                    basename(fpath),
                    e,
                )

                error = e.response.json().get(
                    "error",
                    "An unexpected error occurred. Sorry for the "
                    "inconvenience.",
                )

                Dialog.showError(
                    "Binary Analysis Logs",
                    f"Unable to download binary analysis logs: {error}",
                )

        inthread(bg_task)


def function_signature(
    state: RevEngState, func_addr: int = 0, func_id: int = 0
) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):

        def bg_task(func_ea: int) -> None:
            try:
                function_ids = []
                if func_id:
                    function_ids.append(func_id)
                else:
                    res: Response = RE_analyze_functions(
                        fpath, state.config.get("binary_id", 0)
                    )

                    start_addr = func_ea - inmain(idaapi.get_imagebase)
                    for function in res.json()["functions"]:
                        if function["function_vaddr"] == start_addr:
                            function_ids.append(function["function_id"])

                res = RE_functions_dump(function_ids)

                for function in res.json()["functions"]:
                    if any(
                        function["function_id"] == function_id
                        for function_id in function_ids
                    ):
                        r_type = (
                            "void"
                            if function["return_type"] == "undefined"
                            else function["return_type"]
                        )
                        params = ", ".join(
                            [
                                f"{param['d_type'].replace('typedef ', '')}"
                                f" {param['name']}"
                                for param in function["params"]
                            ]
                        )

                        func_sig = (
                            f"{r_type} {inmain(idc.get_func_name, func_ea)}"
                            f"({params})"
                        )

                        if inmain(idc.SetType, func_ea, func_sig):
                            IDAUtils.refresh_pseudocode_view(func_ea)

                            logger.info(
                                "New function declaration '%s' set at"
                                " address 0x%X",
                                func_sig,
                                func_ea,
                            )
                        else:
                            logger.warning(
                                "Failed to set function declaration '%s' at"
                                " address 0x%X",
                                func_sig,
                                func_ea,
                            )
                            Dialog.showInfo(
                                "Function Declaration",
                                "Failed to update the function declaration"
                                f" with:\n{func_sig}",
                            )
            except HTTPError as e:
                logger.error(
                    "Unable to obtain function argument details. %s",
                    e
                )

                error = e.response.json().get(
                    "error",
                    "An unexpected error occurred. Sorry for the"
                    " inconvenience.",
                )
                Dialog.showError(
                    "Function Signature",
                    f"Failed to obtain function argument details: {error}",
                )

        inthread(
            bg_task,
            idc.get_func_attr(
                func_addr if func_addr > 0 else idc.here(), idc.FUNCATTR_START
            ),
        )


def analysis_history(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):

        def bg_task() -> None:
            try:
                sha_256_hash = inmain(
                    idaapi.retrieve_input_file_sha256).hex()
                res: Response = RE_users_me()
                my_user = res.json().get("data", {}).get("username", "")
                res: Response = RE_recent_analysis_v2(
                    search=sha_256_hash, users=[my_user]
                )

                results = res.json().get("data", {}).get("results", [])

                results = list(
                    filter(
                        lambda analysis: analysis["is_owner"],
                        results,
                    )
                )

                results.sort(
                    key=lambda binary: datetime.fromisoformat(
                        binary["creation"]
                    ).timestamp(),
                    reverse=True,
                )

                models: Response = RE_models()
                models = models.json().get("models", [])
                models_mapper = {}
                for model in models:
                    models_mapper[model["model_id"]] = model["model_name"]

                binaries = []
                today = date.today()

                for analysis in results:
                    creation = datetime.fromisoformat(
                        analysis["creation"]
                    ).astimezone()

                    binaries.append(
                        (
                            analysis.get("binary_name"),
                            str(analysis["binary_id"]),
                            analysis["status"],
                            (
                                creation.strftime("Today at %H:%M:%S")
                                if creation.date() == today
                                else (
                                    creation.strftime("Yesterday at %H:%M:%S")
                                    if creation.date() == today - timedelta(
                                        days=1
                                    )
                                    else creation.strftime(
                                        "%Y-%m-%d, %H:%M:%S"
                                    )
                                )
                            ),
                            models_mapper[analysis["model_id"]],
                        )
                    )

                    inmain(
                        state.config.database.add_analysis,
                        analysis["sha_256_hash"],
                        analysis["binary_id"],
                        analysis["status"],
                        analysis["creation"],
                    )

                if len(binaries):
                    f = inmain(StatusForm, state, binaries)
                    inmain(f.Show)
                    inmain(f.Free)
                else:
                    logger.info("%s not yet analyzed", basename(fpath))
                    Dialog.showInfo(
                        "Binary Analysis History",
                        f"{basename(fpath)} binary not yet analyzed.",
                    )
            except HTTPError as e:
                logger.error("Unable to obtain binary analysis history. %s", e)

                error = e.response.json().get(
                    "error",
                    "An unexpected error occurred. Sorry for the "
                    "inconvenience.",
                )
                Dialog.showError(
                    "Binary Analysis History",
                    f"Failed to obtain binary analysis history: {error}",
                )

        inthread(bg_task)


def load_recent_analyses(state: RevEngState) -> None:
    if state.config.is_valid():

        def bg_task() -> None:
            try:
                res: Response = RE_users_me()
                my_user = res.json().get("data", {}).get("username", "")
                res: Response = RE_recent_analysis_v2(
                    search=sha_256_hash, users=[my_user])

                results = res.json().get("data", {}).get("results", [])

                results = list(
                    filter(
                        lambda analysis: analysis["is_owner"],
                        results,
                    )
                )

                models: Response = RE_models()
                models = models.json().get("models", [])
                models_mapper = {}
                for model in models:
                    models_mapper[model["model_id"]] = model["model_name"]

                for analysis in results:
                    inmain(
                        state.config.database.add_upload,
                        analysis["binary_name"],
                        analysis["sha_256_hash"],
                    )
                    inmain(
                        state.config.database.add_analysis,
                        analysis["sha_256_hash"],
                        analysis["binary_id"],
                        analysis["status"],
                        analysis["creation"],
                        models_mapper[analysis["model_id"]],
                    )

                if len(results) > 0:
                    # sort results by creation date and get the most recent
                    results.sort(
                        key=lambda binary: datetime.fromisoformat(
                            binary["creation"]
                        ).timestamp(),
                        reverse=True,
                    )

                    most_recent = results[0]

                    state.config.set(
                        "binary_id",
                        most_recent["binary_id"]
                    )

                    analysis_id = most_recent.get("analysis_id", 0)
                    state.config.set("analysis_id", analysis_id)

                    logger.info(
                        f"Saving current analysis ID {analysis_id}"
                    )

                    # We always want to auto synchronize the functions
                    # names
                    done, _ = is_analysis_complete(state, fpath)
                    if done:
                        inmain(
                            sync_functions_name,
                            state,
                            fpath,
                            analysis_id
                        )
                else:
                    state.config.set("binary_id", None)
                    state.config.set("analysis_id", None)

                # params = [sha_256_hash]

                # binaries = list(
                #     filter(
                #         lambda binary: binary["sha_256_hash"] == sha_256_hash,
                #         RE_search(fpath).json()["query_results"],
                #     )
                # )

                # if len(binaries) == 0:
                #     state.config.set("binary_id", None)
                # else:
                #     params += [binary["binary_id"] for binary in binaries]

                #     inmain(
                #         state.config.database.execute_sql,
                #         f"DELETE FROM analysis WHERE sha_256_hash = ? AND "
                #         "binary_id NOT IN "
                #         f"({('?, ' * len(binaries))[:-2]})",
                #         tuple(params),
                #     )

                #     state.config.set(
                #         "binary_id",
                #         inmain(
                #             state.config.database.get_last_analysis,
                #             sha_256_hash,
                #         ),
                #     )
                #     bin_id = state.config.get("binary_id", 0)

                #     if bin_id > 0:
                #         resp = RE_analysis_lookup(
                #             bin_id
                #         ).json()

                #         analysis_id = resp.get("analysis_id", 0)
                #         state.config.set("analysis_id", analysis_id)

                #         logger.info(
                #             f"Saving current analysis ID {analysis_id}")

                #         # We always want to auto synchronize the functions
                #         # names
                #         done, _ = is_analysis_complete(state, fpath)
                #         if done:
                #             inmain(sync_functions_name,
                #                    state, fpath, analysis_id)
            except (HTTPError, RequestException) as e:
                logger.error("Error getting recent analyses: %s", e)

        fpath = idc.get_input_file_path()
        sha_256_hash = idaapi.retrieve_input_file_sha256().hex()

        inthread(bg_task)


def sync_functions_name(
        state: RevEngState,
        fpath: str,
        analysis_id: int = 0
) -> None:
    if state.config.is_valid() and fpath and isfile(fpath):

        def bg_task() -> None:
            try:
                res: dict = RE_functions_list(analysis_id=analysis_id).json()

                functions = res.get("data", {}).get("functions", [])
                function_list = []
                # for function in functions:
                # we have 2 possibilities:
                # 1. the function we received exists in Ghidra but not in IDA
                #    in this case we will create a new function in IDA
                # 2. the function we received exists in IDA too, but with a
                #    different name
                #    in this case 2 things can happen:
                #    2.1 the function name in IDA begins with sub_ and we will
                #        rename it with the remote name
                #    2.2 the function name in IDA is different from the remote
                #        name and we will rename it with the remote name
                #    2.3 the function name in IDA is different but the remote
                #        name is a sub_ function and we will rename it with
                #        the local name

                # first let's find all the remote functions which does not
                # exist locally, to do so, just check all the functions in
                # functions for which the function_vaddr is not in
                # ida_functions

                missing_functions = list(
                    filter(
                        lambda func: func["function_vaddr"] not in
                        ida_functions.keys(),
                        functions,
                    )
                )

                for missing in missing_functions:
                    missing_data = {
                        "op": SyncOp.CREATE,
                        "function_id": missing["function_id"],
                        "function_name": missing["function_name"],
                        "function_vaddr": missing["function_vaddr"],
                    }
                    reason = f"Function '{missing['function_name']}' is" \
                        " missing in IDA but exists in RevEng.AI"
                    function_list.append(
                        (
                            CheckableItem(
                                data=missing_data,
                                checked=True,
                            ),
                            missing["function_name"],
                            "N/A",
                            hex(missing["function_vaddr"] + base_addr),
                            "LOCAL",
                            reason
                        )
                    )

                # step 2 is to find all the functions which exist locally and
                # remotely, and check if the name is different or not

                different_functions = list(
                    filter(
                        lambda func: func["function_vaddr"] in
                        ida_functions.keys() and
                        ida_functions[func["function_vaddr"]] !=
                        func["function_name"],
                        functions,
                    )
                )

                for different in different_functions:
                    # in case 2.1 and 2.2 we will rename the function in IDA
                    # with the remote name
                    # in case 2.3 we will rename remote name with the local
                    # name
                    if different["function_name"].startswith("sub_"):
                        # remote name is sub_ and we will rename it with the
                        # local name
                        different_data = {
                            "op": SyncOp.UPDATE,
                            "function_id": different["function_id"],
                            "function_name": ida_functions[
                                different["function_vaddr"]
                            ],
                            "function_vaddr": different["function_vaddr"],
                        }
                        new_name = ida_functions[
                            different["function_vaddr"]
                        ]
                        old_name = different["function_name"]
                        flavor = "REMOTE"
                        reason = "Remote function " \
                            f"'{different['function_name']}'"\
                            " is anonymous while local one has " \
                            f"'{ida_functions[different['function_vaddr']]}'"
                    else:
                        # local name is not updated with the remote name
                        # we will rename it with the remote name in any case
                        different_data = {
                            "op": SyncOp.UPDATE,
                            "function_id": different["function_id"],
                            "function_name": different["function_name"],
                            "function_vaddr": different["function_vaddr"],
                        }
                        new_name = different["function_name"]
                        old_name = ida_functions[
                            different["function_vaddr"]
                        ]
                        flavor = "LOCAL"
                        reason = "Local function " \
                            f"'{ida_functions[different['function_vaddr']]}'" \
                            "is not in sync with remote one " \
                            f"'{different['function_name']}'"

                    function_list.append(
                        (
                            CheckableItem(
                                data=different_data,
                                checked=True,
                            ),
                            new_name,
                            old_name,
                            hex(different["function_vaddr"] + base_addr),
                            flavor,
                            reason
                        )
                    )

                if len(function_list):
                    dialog = inmain(
                        SyncFunctionsDialog,
                        state,
                        fpath,
                        function_list
                    )
                    inmain(dialog.exec_)
            except HTTPError as e:
                resp = e.response.json()
                detail = resp.get("detail", [])
                error = "Unexpected error occurred,"
                " sorry for the inconvenience."
                if len(detail) > 0:
                    error = detail[0].get("msg", error)
                logger.error(
                    f"Error during function synchronization: {error}"
                )

        ida_functions = {}
        base_addr = idaapi.get_imagebase()

        for func_ea in Functions():
            function_addr = idc.get_func_attr(
                func_ea,
                idc.FUNCATTR_START
            ) - base_addr

            ida_functions[function_addr] = IDAUtils.get_func_name(
                func_ea
            )

        inthread(bg_task)


def function_breakdown(state: RevEngState, function_id: int = 0) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):

        def bg_task(func_ea: int, func_id: int = 0) -> None:
            func_name = inmain(IDAUtils.get_demangled_func_name, func_ea)

            if not func_id:
                done, status = is_analysis_complete(state, fpath)
                if not done:
                    Dialog.showInfo(
                        "Function Breakdown",
                        "Unable to fulfil your request at this time.\nBinary"
                        f" analysis status: {status}",
                    )
                    return

                func_ea -= inmain(idaapi.get_imagebase)

                try:
                    inmain(
                        idaapi.show_wait_box,
                        "HIDECANCEL\nGetting information on the function"
                        f" breakdown of {func_name}…",
                    )

                    res: Response = RE_analyze_functions(
                        fpath, state.config.get("binary_id", 0)
                    )

                    func_id = next(
                        (
                            function["function_id"]
                            for function in res.json()["functions"]
                            if function["function_vaddr"] == func_ea
                        ),
                        0,
                    )
                except HTTPError as e:
                    logger.error(
                        "Error getting function list: %s",
                        e.response.json().get(
                            "error",
                            "An unexpected error occurred. Sorry for the"
                            " inconvenience.",
                        ),
                    )
                except RequestException as e:
                    logger.error("An unexpected error has occurred. %s", e)
                finally:
                    inmain(idaapi.hide_wait_box)

            if func_id:
                logger.info(
                    "Redirection to the WEB browser to display the function"
                    " breakdown ID %d | %s",
                    func_id,
                    func_name,
                )

                inmain(
                    idaapi.open_url,
                    f"{state.config.PORTAL}/function/{func_id}",
                )

        inthread(
            bg_task,
            idc.get_func_attr(idc.here(), idc.FUNCATTR_START),
            function_id,
        )


def generate_function_data_types(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()

    if is_condition_met(state, fpath):

        @wait_box_decorator_noclazz(
            "HIDECANCEL\nGenerating data types at binary level…",
        )
        def bg_task() -> None:
            done, status = is_analysis_complete(state, fpath)
            if done:
                try:
                    analysis_id = state.config.get("analysis_id", 0)
                    logger.info(
                        f"Generating data type for analysis ID: {analysis_id}"
                    )

                    function_ids = []

                    logger.info(
                        "Gathering a list of functions to"
                        " generate data types on"
                    )

                    res: dict = RE_analyze_functions(
                        fpath, state.config.get("binary_id", 0)
                    ).json()

                    for function in res.get("functions", []):
                        function_ids.append(function["function_id"])

                    res: dict = RE_functions_data_types(
                        function_ids=function_ids,
                    ).json()

                    status = res.get("status", False)

                    if status:
                        logger.info(
                            "Successfully started the generation of functions"
                            " data types"
                        )

                        Dialog.showInfo(
                            "Function Types",
                            "Successfully started the generation of functions"
                            " data types",
                        )
                    else:
                        Dialog.showInfo(
                            "Function Types",
                            "Failed to generate function data types"
                        )

                except HTTPError as e:
                    resp = e.response.json()
                    error = resp.get(
                        "error",
                        "An unexpected error occurred. Sorry for the"
                        " inconvenience.",
                    )
                    logger.error(
                        f"Failed to generate function data types: {error}"
                    )
                    Dialog.showError(
                        "Function Types",
                        f"Failed to generate function data types: {error}",
                    )
            else:
                Dialog.showError(
                    "Function Types",
                    "Unable to complete your request at this time."
                    " Binary analysis is not yet complete.",
                )

        inthread(bg_task)


@wait_box_decorator_noclazz(
    "HIDECANCEL\nApplying data types to functions…",
)
def apply_function_data_types(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()
    if is_condition_met(state, fpath):
        try:
            logger.info("Function data types application started")
            logger.info("Getting the list of functions to apply data types")

            local_functions = {}

            image_base = idaapi.get_imagebase()

            for func_ea in Functions():
                local_functions[func_ea - image_base] = {
                    "name": IDAUtils.get_demangled_func_name(func_ea),
                    "addr": func_ea
                }

            res: dict = RE_analyze_functions(
                fpath, state.config.get("binary_id", 0)
            ).json()

            function_ids = []
            function_mapper = {}
            functions = res.get("functions", [])

            for function in functions:
                function_ids.append(function["function_id"])
                func_vaddr = function["function_vaddr"]
                item = local_functions.get(func_vaddr)
                if item:
                    function_mapper[function["function_id"]] = item["addr"]
                else:
                    logger.warning(
                        f"Skipping fid: {function['function_id']},"
                        " not found in IDA"
                    )

            import_data_types(
                function_ids=function_ids,
                function_mapper=function_mapper,
            )
        except HTTPError as e:
            resp: dict = e.response.json()
            error = resp.get(
                "error",
                "An unexpected error occurred. Sorry for the inconvenience.",
            )
            logger.error(f"Failed to apply function data types: {error}")
            Dialog.showError(
                "Function Types",
                f"Failed to apply function data types: {error}",
            )
    else:
        Dialog.showInfo("Function Types", "Unable to process function types")


def ai_decompile(state: RevEngState) -> None:
    def error_and_close_view(cb: callable, error: str) -> None:
        Dialog.showError(
            "Error during AI decompilation",
            f"Unable to continue with AI decompilation: {error}",
        )
        logger.error(f"Error during AI decompilation: {error}")
        idaapi.execute_sync(lambda: cb(None), idaapi.MFF_FAST)
        return None

    def get_api_error(res: dict) -> str:
        errors = res.get("errors", [])
        if len(errors) == 0:
            return "An unexpected error occurred. Sorry for the inconvenience."
        return errors[0].get("message", "An unexpected error occurred.")

    def bg_task(start_addr: int, callback) -> None:
        try:
            logger.info("Analyzing functions for AI decompilation")
            res: dict = RE_analyze_functions(
                fpath, state.config.get("binary_id", 0)
            ).json()

            if not res.get("success", False):
                return error_and_close_view(
                    callback,
                    "Unable to analyze functions for AI"
                    " decompilation"
                )

            functions: list[dict] = res.get("functions", [])

            target_function = next(
                (
                    function
                    for function in functions
                    if function["function_vaddr"] == start_addr
                ),
                None,
            )

            if target_function is None:
                return error_and_close_view(
                    callback, "Function not found in the analysis results"
                )

            logger.info(
                "Decompiling function "
                f"{hex(target_function['function_vaddr'])}"
                f" with id {target_function['function_id']}"
            )

            res = RE_poll_ai_decompilation(
                target_function["function_id"],
                summarise=True,
            ).json()

            if not res.get("status", False):
                return error_and_close_view(callback, get_api_error(res))

            poll_status = res.get("data").get("status", "uninitialised")
            logger.info(f"Polling AI decompilation: {poll_status}")

            if poll_status == "uninitialised":
                logger.info("Starting AI Decompilation")

                res = RE_begin_ai_decompilation(
                    target_function["function_id"]
                ).json()

                if not res.get("status", False):
                    return error_and_close_view(callback, get_api_error(res))

                logger.info("AI Decompilation started")

            uninitialised_count = 0

            for _ in range(5):
                # wait for the decompilation to complete
                logger.info("Waiting for AI decompliation to start/complete")
                sleep(1)

                # poll again the status
                res = RE_poll_ai_decompilation(
                    target_function["function_id"],
                    summarise=True,
                ).json()

                if not res.get("status", False):
                    return error_and_close_view(callback, get_api_error(res))

                poll_status = res.get("data").get("status", "uninitialised")

                if poll_status == "uninitialised":
                    uninitialised_count += 1
                elif poll_status == "error":
                    return error_and_close_view(
                        callback,
                        "AI Decompilation failed. This could be due to an"
                        " error in the decompilation process or the function"
                        " not being supported (Windows).",
                    )
                else:
                    logger.info(f"Polling AI decompilation: {poll_status}")

                if uninitialised_count == 5:
                    return error_and_close_view(
                        callback,
                        "AI Decompilation is taking longer than expected."
                        " This could be due to an error in the decompilation"
                        " process or the function not being supported.",
                    )

                if poll_status == "success":
                    break

            logger.info("AI Decompilation completed")
            decompilation_data: dict = res.get("data", {})

            c_code = decompilation_data.get("decompilation", "")

            function_mapping_full: dict = decompilation_data.get(
                "function_mapping_full",
                {}
            )

            if function_mapping_full is None:
                function_mapping_full = {}

            inverse_string_map: list = function_mapping_full.get(
                "inverse_string_map",
                {}
            )

            inverse_function_map: list = function_mapping_full.get(
                "inverse_function_map",
                {}
            )

            for key, value in inverse_string_map.items():
                c_code = c_code.replace(key, value.get("string", key))

            # use ai_summary rather than summary
            summary = decompilation_data.get("ai_summary", "")
            if summary is None:
                summary = ""

            for key, value in inverse_function_map.items():
                val = value.get("name", key)
                if val.startswith("<EXTERNAL>::"):
                    val = val.replace("<EXTERNAL>::", "")
                if val.startswith("."):
                    val = val[1:]
                c_code = c_code.replace(key, val)
                summary = summary.replace(key, val)

            logger.info("Update UI with decompiled code")
            idaapi.execute_sync(lambda: callback(
                (c_code, summary)), idaapi.MFF_FAST)
        except HTTPError as e:
            error = e.response.json().get(
                "error",
                "An unexpected error occurred. Sorry for the inconvenience.",
            )
            return error_and_close_view(callback, error)
        except ConnectionAbortedError:
            error = "An unexpected error occurred. "\
                "Sorry for the inconvenience."
            logger.error(
                f"Error during AI decompilation: {error}\n{tb.format_exc()}")
            return error_and_close_view(callback, error)

    def handle_ai_decomp(decomp_data):
        if decomp_data is not None:
            try:
                if isinstance(decomp_data, tuple):
                    c_code, summary = decomp_data
                    sv.set_code(c_code, summary)
            except Exception as e:
                logger.info(f"Error: {e} \n{tb.format_exc()}")
        else:
            # An error happened, destroy the view
            sv.Close()

    fpath = idc.get_input_file_path()
    if is_condition_met(state, fpath):
        ea = idaapi.get_screen_ea()
        func_ea = ida_funcs.get_func(ea)
        if func_ea:
            func_name = IDAUtils.get_demangled_func_name(func_ea.start_ea)
            image_base = idaapi.get_imagebase()  # Get the image base address
            # subtract the image base address from the start address
            start_addr = func_ea.start_ea - image_base
            logger.info(
                "Starting AI Decompilation of function "
                f"{hex(func_ea.start_ea)}"
            )
            try:
                # Create a custom viewer subview for the decompiled code4
                sv: AICodeViewer = AICodeViewer()
                if sv.Create(f"AI Decompilation of {func_name}"):
                    sv.ClearLines()
                    sv.AddLine("Please wait while the function is decompiled")
                    sv.Show()
            except Exception as e:
                print(f"Error: {e}")
            inthread(bg_task, start_addr, handle_ai_decomp)


def auto_unstrip(state: RevEngState) -> None:
    fpath = idc.get_input_file_path()
    if is_condition_met(state, fpath) and ASKBTN_YES == ask_buttons(
        "Auto Unstrip",
        "Cancel",
        "",
        idaapi.ASKBTN_YES,
        "Auto Unstrip Binary\n\n"
        "Using official RevEngAI sources, function names will be"
        " recovered based on a low similarity threshold and"
        " limited to available debug symbols.\n\n"
        "Functions will be renamed automatically for easier analysis.",
    ):
        auto_unstrip = AutoUnstrip(state)

        def bg_task() -> None:
            try:
                inmain(
                    idaapi.show_wait_box,
                    "HIDECANCEL\nAuto Unstripping binary…",
                )

                matched = auto_unstrip.unstrip()
                if matched > 0:
                    Dialog.showInfo(
                        "Auto Unstrip",
                        "Auto Unstrip completed successfully!\n"
                        f"A total of {matched} symbols were renamed."
                    )
                else:
                    Dialog.showInfo(
                        "Auto Unstrip",
                        "Auto Unstrip completed, "
                        "but no symbols were renamed.\n"
                        "This may indicate that all symbols were already"
                        " properly named or\n"
                        "no matches were found during the process."
                    )
            except HTTPError as e:
                res: dict = e.response.json()
                logger.error(
                    f"Unable to auto unstrip binary: {res.get('error')}"
                )
            finally:
                inmain(idaapi.hide_wait_box)

        inthread(
            bg_task,
        )


def generate_summaries(state: RevEngState, function_id: int = 0) -> None:
    fpath = idc.get_input_file_path()

    def ask_btn() -> int:
        return idaapi.ask_buttons(
            "Generate",
            "Cancel",
            "",
            idaapi.ASKBTN_YES,
            "HIDECANCEL\nWould you like to generate summaries?\n\n"
            "The cost of this operation is estimated to be 0.045 credits,\n"
            "and will generate summaries for each node in the flow.\n\n"
            "This action is irreversible and cannot be undone.",
        )

    if is_condition_met(state, fpath) and idaapi.ASKBTN_YES == ask_btn():

        def bg_task(func_ea: int, func_id: int = 0) -> None:
            func_name = inmain(IDAUtils.get_demangled_func_name, func_ea)

            if not func_id:
                done, status = is_analysis_complete(state, fpath)
                if not done:
                    Dialog.showInfo(
                        "Generate Summaries",
                        "Unable to fulfil your request at this time.\nBinary"
                        f" analysis status: {status}",
                    )
                    return

                func_ea -= inmain(idaapi.get_imagebase)

                try:
                    res: Response = RE_analyze_functions(
                        fpath, state.config.get("binary_id", 0)
                    )

                    func_id = next(
                        (
                            function["function_id"]
                            for function in res.json()["functions"]
                            if function["function_vaddr"] == func_ea
                        ),
                        0,
                    )
                except HTTPError as e:
                    logger.error(
                        "Error getting function list: %s",
                        e.response.json().get(
                            "error",
                            "An unexpected error occurred. Sorry for the"
                            " inconvenience.",
                        ),
                    )
                except RequestException as e:
                    logger.error("An unexpected error has occurred. %s", e)

            if func_id:
                logger.info(
                    "Generates block summaries for function ID %d | %s",
                    func_id,
                    func_name,
                )

                try:
                    inmain(
                        idaapi.show_wait_box,
                        "HIDECANCEL\nGenerating block summaries for"
                        f" {func_name}…",
                    )

                    res: Response = RE_generate_summaries(func_id)

                    # TODO Need to process the response
                except HTTPError as e:
                    logger.error(
                        "Error generating block summaries: %s",
                        e.response.json().get(
                            "error",
                            "An unexpected error occurred."
                        ),
                    )
                finally:
                    inmain(idaapi.hide_wait_box)

        inthread(
            bg_task,
            idc.get_func_attr(idc.here(), idc.FUNCATTR_START),
            function_id,
        )


def is_analysis_complete(state: RevEngState, fpath: str) -> tuple[bool, str]:
    try:
        bid = state.config.get("binary_id", 0)

        res: Response = RE_status(fpath, bid)

        status = res.json()["status"]

        if bid:
            if status in (
                "Queued",
                "Processing",
            ):
                periodic_check(fpath, bid)

            inmain(state.config.database.update_analysis, bid, status)

        return status == "Complete", status
    except HTTPError as e:
        error = e.response.json().get(
            "error",
            "An unexpected error occurred. Sorry for the inconvenience.",
        )

        # if any(word in error.lower()for word in ("invalid", "denied",)):
        #     inmain(upload_binary, state)

        logger.error("Error getting binary analysis status: %s", error)
        return False, (
            error
            if any(
                word in error.lower()
                for word in (
                    "invalid",
                    "denied",
                )
            )
            else "Processing"
        )


def is_condition_met(state: RevEngState, fpath: str) -> bool:
    if not state.config.is_valid():
        setup_wizard(state)
    elif not fpath or not isfile(fpath):
        idc.warning(
            "The target file was not found on disk. Has it "
            "been moved or renamed?"
        )
    else:
        return True
    return False


def is_file_supported(state: RevEngState, fpath: str) -> bool:
    try:

        logger.info(f"Checking file support: {fpath}")

        file_format, isa_format = file_type_ida()

        logger.info(
            f"Underlying binary: {fpath} -> format: {file_format},"
            f" target: {isa_format}"
        )

        if any(
            file_format == fmt for fmt in state.config.OPTIONS.get(
                "file_options",
                []
            )
        ) and any(
            isa_format == fmt for fmt in state.config.OPTIONS.get(
                "isa_options",
                []
            )
        ):
            return True
        
        idc.warning(
            f"{file_format} file format is not currently supported by "
            "RevEng.AI"
        )
    except Exception as e:
        logger.error(f"Error checking file support: {e}")
        pass

    return False


def about(_) -> None:
    f = AboutForm()
    f.Show()
    f.Free()


def update(_) -> None:
    try:
        res: Response = get(
            "https://api.github.com/repos/revengai/reai-ida/releases/latest",
            timeout=30,
        )

        res.raise_for_status()

        j = res.json()
        if 'tag_name' not in j:
            raise ValueError("Invalid response from GitHub API")

        version_stable = j["tag_name"].lstrip("v")

        f = UpdateForm(
            "You're already using the latest stable version!"
            if version_stable == __version__
            else f"The latest stable version is {version_stable}. Please "
            "update to stay current.",
            version=version_stable
        )

        f.Show()
        f.Free()
    except RequestException as e:
        logger.warning(
            "RevEng.AI failed to connect to GitHub to poll for the"
            " latest plugin update. %s",
            e,
        )
        Dialog.showInfo(
            "Check for Update",
            "RevEng.AI has failed to connect to the internet (GitHub)."
            " Try again later.",
        )


def periodic_check(state: RevEngState, fpath: str, binary_id: int) -> None:
    def _worker(bid: int, interval: float = 60):
        try:
            status = RE_status(fpath, bid).json()["status"]

            if status in (
                "Queued",
                "Processing",
            ):
                if inmain(idc.get_input_file_path) == fpath:
                    Timer(
                        interval,
                        _worker,
                        args=(
                            bid,
                            interval,
                        ),
                    ).start()

                    logger.info(
                        "Waiting for analysis completition for: %s [%d] check "
                        "again in %d seconds",
                        basename(fpath),
                        bid,
                        interval,
                    )
            else:
                logger.info(
                    "Analysis status for: %s [%d] is %s",
                    basename(fpath),
                    bid,
                    status,
                )
                logger.info("Pushing function names to platform")
                inmain(
                    push_function_names,
                    state,
                )
        except RequestException as ex:
            logger.error(
                "Error getting binary analysis status. Reason: %s",
                ex
            )

    Timer(30, _worker, args=(binary_id,)).start()
    logger.info(
        "Scheduling binary analysis status for: %s [%d]",
        basename(fpath),
        binary_id,
    )


def toolbar(state: RevEngState) -> None:
    """
    Workaround to show RevEng.AI logo in toolbar to create menu bar when
    clicked
    """
    from revengai.ida_ui import RevEngConfigForm_t

    form = RevEngConfigForm_t(state)
    form.register_actions(False)
    del form
    
def view_function_in_portal(state: RevEngState):
    try:
        fpath = idc.get_input_file_path()
        base_addr = idaapi.get_imagebase()
        res: Response = RE_search(fpath)
        binaries = res.json()["query_results"]
        for binary in binaries:
            analysis = RE_get_analysis_id_from_binary_id(binary["binary_id"]).json()
            functions = RE_get_functions_from_analysis(analysis["analysis_id"]).json()["data"]["functions"]
            found = False
            for function in functions:
                if function["function_vaddr"] == ida_funcs.get_func(idc.get_screen_ea()).start_ea - base_addr:
                    found = True
                    inmain(idaapi.open_url, f"{state.config.PORTAL}/function/{function['function_id']}")
                    break
            if found:
                break
        if not found:
            Dialog.showInfo("Function URL", "Function not found in portal")
    except Exception as e:
        logger.error(f"Error getting function in portal: {e}")
