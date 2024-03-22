from os.path import exists

from idc import get_input_file_path
from reait.api import RE_upload, RE_analyse, RE_status, RE_embeddings
from requests import HTTPError, Response

from revengai.conf import RevEngConfiguration
from revengai.gui.dialog import Dialog
from revengai.logger import plugin_logger
from revengai.wizard.wizard import RevEngSetupWizard


def setup_wizard(config: RevEngConfiguration) -> None:
    RevEngSetupWizard(config.base).exec()


def upload_binary(config: RevEngConfiguration) -> None:
    if not config.base.config.is_valid():
        setup_wizard(config)
    else:
        path = get_input_file_path()

        if exists(path):
            try:
                res: Response = RE_upload(path)
                hash = res.json()["sha_256_hash"]

                res = RE_analyse(fpath=path, model=config.base.config.get("model"))
                res.json()["binary_id"]
            except HTTPError as e:
                plugin_logger.error(f"[EXCEPTION] -> {e}")


def check_analyze(config: RevEngConfiguration) -> None:
    if not config.base.config.is_valid():
        setup_wizard(config)
    else:
        path = get_input_file_path()

        if exists(path):
            try:
                res: Response = RE_status(fpath=path, model_name=config.base.config.get("model"))
                status = res.json()["status"]

                Dialog.showInfo("Check Analysis Status", f"Status: {status}")
            except HTTPError as e:
                Dialog.showError("Check Analysis Status",
                                 "Error getting status\n\nCheck:\n"
                                 "  • You have downloaded your binary id from the portal.\n"
                                 "  • You have uploaded the current binary to the portal.")


def auto_analyze(config: RevEngConfiguration) -> None:
    if not config.base.config.is_valid():
        setup_wizard(config)
    else:
        path = get_input_file_path()

        if exists(path):
            try:
                res: Response = RE_embeddings(fpath=path, model_name=config.base.config.get("model"))
                res.json()
            except HTTPError as e:
                Dialog.showError("Auto Analysis", e.response.json()["error"])
    pass
