# -*- coding: utf-8 -*-

from os.path import exists, basename

import idc
from requests import HTTPError, Response, post

from reait.api import RE_upload, RE_analyse, RE_status, reveng_req
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
        path = idc.get_input_file_path()

        if exists(path):
            try:
                RE_upload(path)

                RE_analyse(fpath=path, model_name=state.config.get("model"), duplicate=True)
            except HTTPError as e:
                Dialog.showInfo("Upload Binary",
                                f"Error analysing {basename(path)}.\nReason: {e.response.json()['error']}")


def check_analyze(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        path = idc.get_input_file_path()

        if exists(path):
            try:
                res: Response = RE_status(fpath=path)

                if isinstance(res, Response):
                    Dialog.showInfo("Check Analysis Status", f"Status: {res.json()['status']}")
                else:
                    Dialog.showError("Check Analysis Status", "No matches found.")
            except Exception:
                Dialog.showError("Check Analysis Status",
                                 "Error getting status\n\nCheck:\n"
                                 "  • You have downloaded your binary id from the portal.\n"
                                 "  • You have uploaded the current binary to the portal.")


def auto_analyze(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        path = idc.get_input_file_path()

        if exists(path):
            dialog = AutoAnalysisDialog(state, path)
            dialog.exec_()


def rename_function(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        path = idc.get_input_file_path()

        if exists(path):
            dialog = FunctionSimularityDialog(state, path)
            dialog.exec_()


def explain_function(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        try:
            # pseudo_code = IDAUtils.disasm_func(idc.here())

            pseudo_code = IDAUtils.decompile_func(idc.here())

            if len(pseudo_code) > 0:
                res: Response = reveng_req(post, "explain", data={pseudo_code})

                res.raise_for_status()
                print(res.text)

                # IDAUtils.set_comment(idc.here(), res.json()["explanation"])
        except HTTPError as e:
            if "error" in e.response.json():
                Dialog.showError("",
                                 f"Error getting function explanation: {e.response.json()['error']}")
