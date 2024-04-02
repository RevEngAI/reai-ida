# -*- coding: utf-8 -*-

import abc

from PyQt5.QtCore import QRect
from PyQt5.QtWidgets import QDialog, QDesktopWidget

from revengai.manager import RevEngState


class BaseDialog(QDialog):
    __metaclass__ = abc.ABCMeta

    def __init__(self, state: RevEngState, fpath: str):
        QDialog.__init__(self)

        self.path = fpath
        self.state = state

        state.config.init_current_analysis()

    def showEvent(self, event):
        super(BaseDialog, self).showEvent(event)

        screen: QRect = QDesktopWidget().screenGeometry()

        # Center the dialog to screen
        self.move(screen.width()  // 2 - self.width()  // 2,
                  screen.height() // 2 - self.height() // 2)
