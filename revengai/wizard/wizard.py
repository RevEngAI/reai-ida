import abc
import logging
from os.path import dirname, join
from platform import system

import idaapi
from PyQt5.QtCore import QRect
from PyQt5.QtGui import QPixmap
from PyQt5.QtWidgets import (
    QWizardPage,
    QFormLayout,
    QLineEdit,
    QLabel,
    QWizard,
    QComboBox,
    QLayout,
    QDesktopWidget,
)
from reait.api import RE_authentication
from requests import HTTPError, RequestException

from revengai.api import RE_models
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState

logger = logging.getLogger("REAI")


class RevEngSetupWizard(QWizard):
    def __init__(self, state: RevEngState, parent=None):
        super(RevEngSetupWizard, self).__init__(parent)

        self.state: RevEngState = state

        self.addPage(UserCredentialsPage(self.state))
        self.addPage(UserAvailableModelsPage(self.state))

        self.setWindowTitle("RevEng.AI Toolkit: Setup Wizard")
        self.setOptions(QWizard.CancelButtonOnLeft |
                        QWizard.NoBackButtonOnStartPage)
        self.setWizardStyle(
            QWizard.MacStyle if system() == "Darwin" else QWizard.ModernStyle
        )
        self.setPixmap(
            (
                QWizard.BackgroundPixmap
                if system() == "Darwin"
                else QWizard.WatermarkPixmap
            ),
            QPixmap(join(dirname(__file__), "..", "resources", "logo.png")),
        )

        self.button(QWizard.FinishButton).clicked.connect(self._save)

    def showEvent(self, event):
        super(QWizard, self).showEvent(event)

        screen: QRect = QDesktopWidget().screenGeometry()

        # Center the dialog to screen
        self.move(
            screen.width() // 2 - self.width() // 2,
            screen.height() // 2 - self.height() // 2,
        )

    def _save(self):
        self.state.config.save()

        # Refresh menu item actions
        try:
            self.state.gui.config_form.register_actions()
        except Exception:
            print("Please choose one of the available models")


class BasePage(QWizardPage):
    __metaclass__ = abc.ABCMeta

    def __init__(self, state: RevEngState, parent=None):
        super().__init__(parent)

        self.state = state

        self.setTitle(self._get_title())
        self.setLayout(self._get_layout())

    @abc.abstractmethod
    def _get_title(self) -> str:
        pass

    @abc.abstractmethod
    def _get_layout(self) -> QLayout:
        pass


class UserCredentialsPage(BasePage):
    def __init__(self, state: RevEngState, parent=None):
        super().__init__(state, parent)

    def initializePage(self):
        self.state.config.restore()

        self.api_key.setText(self.state.config.get("apikey"))
        self.server_url.setText(self.state.config.get("host"))

    def validatePage(self):
        if not any(c.text() == "" for c in [self.api_key, self.server_url]):
            try:
                idaapi.show_wait_box("HIDECANCEL\nChecking configuration…")

                self.state.config.set("apikey", self.api_key.text())
                self.state.config.set("host", self.server_url.text())

                response = RE_authentication().json()

                logger.info("%s", response["message"])

                response = RE_models().json()

                self.state.config.set(
                    "models", [model["model_name"]
                               for model in response["models"]]
                )
                return True
            except HTTPError as e:
                # Reset host and API key if an error occurs
                self.state.config.set("host")
                self.state.config.set("apikey")

                logger.error(
                    "Unable to retrieve any of the available models. %s", e)

                error = e.response.json().get(
                    "error",
                    "An unexpected error occurred. Sorry for the"
                    " inconvenience.",
                )
                Dialog.showError("Setup Wizard", error)
            except RequestException as e:
                logger.error("An unexpected error has occurred. %s", e)
            finally:
                idaapi.hide_wait_box()
        return False

    def _get_title(self) -> str:
        return "RevEng.AI Credentials"

    def _get_layout(self) -> QLayout:
        self.api_key = QLineEdit(self)
        self.api_key.setClearButtonEnabled(True)
        self.api_key.setToolTip("API key from your account settings")

        self.server_url = QLineEdit(self)
        self.server_url.setToolTip("URL hosting the RevEng.AI platform")

        layout = QFormLayout(self)

        layout.addWidget(
            QLabel(
                '<span style="font-weight:bold">'
                'Setup Account Information'
                '</span>'
            )
        )
        layout.addRow(QLabel("Personal Key:"), self.api_key)
        layout.addRow(QLabel("Hostname:"), self.server_url)

        return layout


class UserAvailableModelsPage(BasePage):
    def __init__(self, state: RevEngState, parent=None):
        super().__init__(state, parent)

        self.setFinalPage(True)

    def _get_title(self) -> str:
        return "Setup Mode"

    def _get_layout(self) -> QLayout:
        self.cbModel: QComboBox = QComboBox(self)

        self.cbModel.setEditable(True)
        self.cbModel.lineEdit().setReadOnly(True)
        self.cbModel.lineEdit().setPlaceholderText("Select…")

        layout = QFormLayout(self)

        layout.addWidget(
            QLabel('<span style="font-weight:bold">Set AI Model</span>'))
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
