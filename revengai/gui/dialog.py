# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import QMessageBox


class Dialog:
    @staticmethod
    def showInfo(title: str, message: str) -> None:
        msgBox = QMessageBox()
        msgBox.setModal(True)
        msgBox.setWindowTitle(title)
        msgBox.setText(message)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.exec()

    @staticmethod
    def showError(title: str, message: str) -> None:
        msgBox = QMessageBox()
        msgBox.setModal(True)
        msgBox.setWindowTitle(title)
        msgBox.setText(message)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.exec()
