# -*- coding: utf-8 -*-

import abc
from sys import platform
from requests import get, HTTPError, Response

from PyQt5.QtWidgets import QWizardPage, QFormLayout, QLineEdit, QLabel, QWizard, QComboBox, QLayout

from reait.api import reveng_req
from revengai.manager import RevEngState

from revengai.logger import plugin_logger


class RevEngSetupWizard(QWizard):
    def __init__(self, state: RevEngState, parent=None):
        super(RevEngSetupWizard, self).__init__(parent)

        self.state: RevEngState = state

        self.addPage(UserCredentialsPage(self.state))

        self.addPage(UserAvailableModelsPage(self.state))

        self.setWindowTitle("RevEng.AI Setup Wizard")
        self.setOptions(QWizard.CancelButtonOnLeft | QWizard.NoBackButtonOnStartPage)
        self.setWizardStyle(QWizard.MacStyle if platform == 'darwin' else QWizard.ModernStyle)

        self.button(QWizard.FinishButton).clicked.connect(self._finishClicked)

    def _finishClicked(self):
        self.state.config.save()


class BasePage(QWizardPage):
    __metaclass__ = abc.ABCMeta

    def __init__(self, state: RevEngState, parent=None):
        super().__init__(parent)

        self.state = state

        self.setTitle(self._getTitle())
        self.setLayout(self._get_layout())

    @abc.abstractmethod
    def _getTitle(self) -> str:
        pass

    @abc.abstractmethod
    def _get_layout(self) -> QLayout:
        pass


class UserCredentialsPage(BasePage):
    def __init__(self, state: RevEngState, parent=None):
        super().__init__(state, parent)

    def initializePage(self):
        self.api_key.setText(self.state.config.get("apikey"))
        self.server_url.setText(self.state.config.get("host"))

    def validatePage(self):
        if not any(c.text() == "" for c in [self.api_key, self.server_url]):
            try:
                res: Response = reveng_req(get, "models")
                res.raise_for_status()

                self.state.config.set("apikey", self.api_key.text())
                self.state.config.set("host", self.server_url.text())
                self.state.config.set("models", res.json()["models"])
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
    def __init__(self, state: RevEngState, parent=None):
        super().__init__(state, parent)

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

        self.cbModel.addItems(self.state.config.get("models"))
        self.cbModel.setCurrentIndex(-1)

    def validatePage(self):
        if self.cbModel.currentIndex() != -1:
            self.state.config.set("models")
            self.state.config.set("model", self.cbModel.currentText())
            return True

        return False
