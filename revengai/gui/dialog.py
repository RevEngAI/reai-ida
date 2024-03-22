from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMessageBox


class Dialog:
    @staticmethod
    def ok_box(msg: str) -> None:
        mb = QtWidgets.QMessageBox()
        mb.setIcon(QtWidgets.QMessageBox.Icon.Information)
        mb.setWindowTitle("Connection check")
        mb.addButton(QtWidgets.QMessageBox.StandardButton.Ok)
        mb.setText(msg)
        mb.exec_()

    @staticmethod
    def showInfo(title: str, message: str) -> None:
        msgBox = QMessageBox()
        msgBox.setModal(True)
        msgBox.setWindowTitle(title)
        msgBox.setText(message)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.exec_()

    @staticmethod
    def showError(title: str, message: str) -> None:
        msgBox = QMessageBox()
        msgBox.setModal(True)
        msgBox.setWindowTitle(title)
        msgBox.setText(message)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.exec_()