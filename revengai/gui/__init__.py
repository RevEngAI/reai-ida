# -*- coding: utf-8 -*-
from os.path import join, dirname

from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtWidgets import QMessageBox


class Requests(object):
    class MsgBox(object):
        def __init__(self, title: str, msg: str, icon: int = QMessageBox.Critical):
            self.title = title
            self.msg = msg
            self.icon = icon

        def __call__(self) -> bool:
            msg_box = QMessageBox()

            msg_box.setModal(True)
            msg_box.setIcon(self.icon)
            msg_box.setWindowTitle(self.title)

            if self.icon == -1:
                msg_box.setIconPixmap(QPixmap(join(dirname(__file__), "../resources/favicon.png")))
            else:
                msg_box.setWindowIcon(QIcon(join(dirname(__file__), "../resources/favicon.png")))

            msg_box.setText(self.msg)
            msg_box.exec_()
            return False  # Don't reschedule
