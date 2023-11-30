from PyQt5 import QtWidgets, QtCore
from revengai.logger import plugin_logger


class AboutView:
    _about = {"Version": "0.0.1", "Author": "Ivan King @systemnt"}

    def __init__(self) -> None:
        self._parent = None

    def view(self) -> QtWidgets.QWidget:
        plugin_logger.debug("<<<")
        container = QtWidgets.QGroupBox("About")
        layout = QtWidgets.QVBoxLayout()

        for k, v in self._about.items():
            l = QtWidgets.QLabel(k + ": " + v)
            l.setAlignment(
                QtCore.Qt.AlignmentFlag.AlignLeft | QtCore.Qt.AlignmentFlag.AlignTop
            )
            l.setSizePolicy(
                QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed
            )
            l.setStyleSheet("font: 8pt;")
            layout.addWidget(l)

        container.setLayout(layout)
        return container
