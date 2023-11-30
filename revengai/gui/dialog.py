from PyQt5 import QtWidgets


class Dialog:
    @staticmethod
    def ok_box(msg: str) -> None:
        mb = QtWidgets.QMessageBox()
        mb.setIcon(QtWidgets.QMessageBox.Icon.Information)
        mb.setWindowTitle("Connection check")
        mb.addButton(QtWidgets.QMessageBox.StandardButton.Ok)
        mb.setText(msg)
        mb.exec_()
