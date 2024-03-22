from sys import platform
from requests import get, HTTPError, Response

from PyQt5.QtWidgets import QWizardPage, QFormLayout, QLineEdit, QLabel, QWizard, QComboBox, QLayout

from reait.api import reveng_req

from revengai.misc.base import Base
from revengai.logger import plugin_logger


class RevEngSetupWizard(QWizard):
    def __init__(self, base: Base, parent=None):
        super(RevEngSetupWizard, self).__init__(parent)

        self.base: Base = base

        self.addPage(UserCredentialsPage(self.base))

        self.addPage(UserAvailableModelsPage(self.base))

        self.setWindowTitle("RevEng.AI Setup Wizard")
        self.setOptions(QWizard.CancelButtonOnLeft | QWizard.NoBackButtonOnStartPage)
        self.setWizardStyle(QWizard.MacStyle if platform == 'darwin' else QWizard.ModernStyle)

        self.button(QWizard.FinishButton).clicked.connect(self._finishClicked)

    def _finishClicked(self):
        self.base.config.persistConfig()


class BasePage(QWizardPage):
    def __init__(self, base: Base, parent=None):
        super().__init__(parent)

        self.base = base

        self.setTitle(self._getTitle())
        self.setLayout(self._get_layout())

    def _getTitle(self) -> str:
        pass

    def _get_layout(self) -> QLayout:
        pass


class UserCredentialsPage(BasePage):
    def __init__(self, base: Base, parent=None):
        super().__init__(base, parent)

    def initializePage(self):
        self.api_key.setText(self.base.config.get("apikey"))
        self.server_url.setText(self.base.config.get("host"))

    def validatePage(self):
        if not any(c.text() == "" for c in [self.api_key, self.server_url]):
            try:
                res: Response = reveng_req(get, "/models")
                res.raise_for_status()

                self.base.config.set("apikey", self.api_key.text())
                self.base.config.set("host", self.server_url.text())
                self.base.config.set("models", res.json()["models"])
                return True
            except HTTPError as e:
                plugin_logger.error(f"[EXCEPTION] -> {e}")
        return False

    def _getTitle(self) -> str:
        return "RevEng.AI Credentials"

    def _get_layout(self) -> QLayout:
        self.api_key = QLineEdit(self)
        self.api_key.setToolTip("API key from your account settings")

        self.server_url = QLineEdit(self)
        self.server_url.setEnabled(False)
        self.server_url.setToolTip("URL hosting the RevEng.ai Server")

        layout = QFormLayout(self)

        layout.addWidget(QLabel("<span style=\"font-weight:bold\">Setup Account Information</span>"))
        layout.addRow(QLabel("API Key:"), self.api_key)
        layout.addRow(QLabel("Hostname:"), self.server_url)

        return layout


class UserAvailableModelsPage(BasePage):
    def __init__(self, base: Base, parent=None):
        super().__init__(base, parent)

        self.setFinalPage(True)

    def _getTitle(self) -> str:
        return "Setup Mode"

    def _get_layout(self) -> QLayout:
        self.cbModel: QComboBox = QComboBox(self)

        layout = QFormLayout(self)

        layout.addWidget(QLabel("<span style=\"font-weight:bold\">Set AI Model</span>"))
        layout.addRow(QLabel("Using Model:"), self.cbModel)

        return layout

    def initializePage(self):
        self.cbModel.clear()

        self.cbModel.addItems(self.base.config.get("models"))
        self.cbModel.setCurrentText(self.base.config.get("model"))

    def validatePage(self):
        if self.cbModel.currentIndex() != -1:
            self.base.config.set("models", None)
            self.base.config.set("model", self.cbModel.currentText())
            return True

        return False
