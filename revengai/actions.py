# -*- coding: utf-8 -*-

from os.path import exists, basename
from requests import HTTPError, Response

from idc import get_input_file_path
from reait.api import RE_upload, RE_analyse, RE_status
from revengai.features.auto_analyze import AutoAnalysisDialog

from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.features.function_simularity import FunctionSimularityDialog
from revengai.wizard.wizard import RevEngSetupWizard


def setup_wizard(state: RevEngState) -> None:
    RevEngSetupWizard(state).exec()


def upload_binary(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        path = get_input_file_path()

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
        path = get_input_file_path()

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
        path = get_input_file_path()

        if exists(path):
            dialog = AutoAnalysisDialog(state, path)
            dialog.exec_()


def rename_functions(state: RevEngState) -> None:
    if not state.config.is_valid():
        setup_wizard(state)
    else:
        path = get_input_file_path()

        if exists(path):
            dialog = FunctionSimularityDialog(state, path)
            dialog.exec_()
