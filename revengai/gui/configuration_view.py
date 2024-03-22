from typing import Union
import idaapi
from PyQt5 import QtWidgets, QtGui, QtCore
from PyQt5.QtGui import QIntValidator

from revengai.api import Endpoint
from revengai.misc.base import Base
from revengai.misc.configuration import Configuration
from revengai.logger import plugin_logger
from revengai.gui.dialog import Dialog
from revengai.wizard.wizard import RevEngSetupWizard


class DropDownBox(QtWidgets.QComboBox):
    """
    Overriden class because QComboBox does not provide a signal for when a user clicks the drop-down arrow
    which makes no sense. Had to extend the class and add our own mouse press event then check what control
    it was triggering on in order to detect someone pressing the drop-down arrow - stupid really, why doesn't
    qt provide this signal.
    """

    def __init__(self, parent, endpoint) -> None:
        super().__init__(parent)
        self._endpoint: Endpoint = endpoint

    def mousePressEvent(self, e: Union[QtGui.QMouseEvent, None]) -> None:
        """
        Adjusted from:
        https://stackoverflow.com/questions/54901248/how-to-know-when-down-arrow-of-combo-box-is-clicked

        with help from:
        https://stackoverflow.com/questions/38584550/customizing-the-qscrollbar-in-pyqt
        """
        opt = QtWidgets.QStyleOptionComboBox()
        self.initStyleOption(opt)
        sc = self.style().hitTestComplexControl(
            QtWidgets.QStyle.ComplexControl.CC_ComboBox, opt, e.pos(), self
        )

        if sc == QtWidgets.QStyle.SubControl.SC_ComboBoxArrow:
            json, resp = self._endpoint.get_models()
            if json is not None and resp.status_code == 200:
                models = json["models"]
                gui_model: QtGui.QStandardItemModel = self.model()
                if models is not None:
                    for m in models:
                        if not len(gui_model.findItems(m, QtCore.Qt.MatchFlag.MatchExactly)) > 0:
                            self.addItem(m)

        # call parent so the drop-down still triggers
        super().mousePressEvent(e)


class ConfigurationView:
    def __init__(self, config: Configuration, endpoint: Endpoint) -> None:
        self.layout = None
        self._configdata = config
        self._parent = None
        self._endpoint = endpoint

    def clicked_update(self) -> None:
        config = {}
        # layout: QtWidgets.QFormLayout = self._parent.sender().parent().layout()
        for i in range(self.layout.rowCount()):
            # use the property we set on the QLineEdit to set the correct key for config
            item: QtWidgets.QLineEdit = self.layout.itemAt(
                i, QtWidgets.QFormLayout.ItemRole.FieldRole
            ).widget()
            if isinstance(item, QtWidgets.QLineEdit):
                config[item.property("config_key")] = item.text()
            elif isinstance(item, DropDownBox):
                config["current_model"] = item.currentText()

        # NOTE - Model is recorded when user selects it from the drop down list
        plugin_logger.debug(f"got new config {config}")
        self._configdata.update(config["host"], config["port"], config["key"], config["current_model"])

    def clicked_clear(self) -> None:
        RevEngSetupWizard(Base()).exec()

        # layout: QtWidgets.QFormLayout = self.view().layout()
        # find parent and get layout object then clear all LineEdit objects inside it
        # layout: QtWidgets.QFormLayout = self._parent.sender().parent().layout()
        for i in range(self.layout.rowCount()):
            item: QtWidgets.QLineEdit = self.layout.itemAt(
                i, QtWidgets.QFormLayout.ItemRole.FieldRole
            ).widget()
            if isinstance(item, QtWidgets.QLineEdit):
                item.clear()

    def clicked_check(self) -> None:
        # TODO - Update ping() to touch the /echo endpoint once this endpoint has been fixed.
        # TODO - if the user enters data directly in to the fields and then clicks check WITHOUT doing Update before
        # this will then fail as the config has yet to be updated via a call to 'Update'
        if self._configdata.is_valid():
            # json, resp = self._endpoint.ping()
            # if resp.status_code == 200:
            #     Dialog.ok_box("OK!")
            # Dialog.ok_box("Not implemented")
            # else:
            #     Dialog.ok_box(f"Failed - response {json} code {resp.status_code}")
            Dialog.ok_box("Not implemented")
        else:
            idaapi.warning("Configuration is not set or valid")

    def record_model(self, idx: int) -> None:
        source: DropDownBox = self._parent.sender()
        val = source.itemText(idx)
        plugin_logger.debug(f"Updating current_model value to {val}")
        self._configdata.config["current_model"] = val

    def view(self) -> QtWidgets.QWidget:
        container = QtWidgets.QGroupBox("Setup Account Information")
        self.layout = QtWidgets.QFormLayout()

        api = QtWidgets.QLineEdit()
        api.setToolTip("API key from your account settings")
        api.setProperty("config_key", QtCore.QVariant("key"))

        host = QtWidgets.QLineEdit()
        host.setToolTip("URL hosting the RevEng.ai Server")
        host.setProperty("config_key", QtCore.QVariant("host"))

        port = QtWidgets.QLineEdit()
        port.setValidator(QIntValidator(0, 65535, self.layout))
        port.setProperty("config_key", QtCore.QVariant("port"))

        # api.setText(self._configdata.config["key"])
        # host.setText(self._configdata.config["host"])
        #
        # if self._configdata.is_valid():
        #     plugin_logger.debug("config detected, pre-entering data")
        #     api.setText(self._configdata.config["key"])
        #     host.setText(self._configdata.config["host"])
        #     port.setText(self._configdata.config["port"])
        # else:
        #     api.setFocus()

        self.layout.addRow(QtWidgets.QLabel("API Key:"), api)
        self.layout.addRow(QtWidgets.QLabel("Hostname:"), host)
        # self.layout.addRow(QtWidgets.QLabel("Port"), port)

        # model dropdown list
        model_dropdown = DropDownBox(None, self._endpoint)
        port.setProperty("current_model", QtCore.QVariant("current_model"))

        model_dropdown.activated.connect(self.record_model)

        # TODO
        # if self._configdata.is_valid():
        #     model_dropdown.addItem(self._configdata.config["current_model"])
        self.layout.addRow(QtWidgets.QLabel("Model:"), model_dropdown)

        # Update button
        update_button = QtWidgets.QPushButton("Save")
        update_button.clicked.connect(self.clicked_update)

        # Clear button
        clear_button = QtWidgets.QPushButton("Clear")
        clear_button.clicked.connect(self.clicked_clear)

        # Check button
        check_button = QtWidgets.QPushButton("Check")
        check_button.clicked.connect(self.clicked_check)

        vbox = QtWidgets.QHBoxLayout()
        vbox.addWidget(update_button)
        vbox.addWidget(clear_button)
        vbox.addWidget(check_button)

        self.layout.addRow(vbox)
        container.setLayout(self.layout)
        return container
