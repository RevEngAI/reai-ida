# -*- coding: utf-8 -*-

from PyQt5.QtCore import pyqtSignal, QThreadPool

from revengai.conf import RevEngConfiguration


class RevEngState(object):
    def __init__(self, config: RevEngConfiguration):
        self.gui = None
        self.config = config

        self.threadpool = QThreadPool.globalInstance()

        self.updateSignal = pyqtSignal()

    def start_plugin(self):
        from revengai.ida_ui import RevEngGUI
        
        self.gui = RevEngGUI(self)
        self.gui.show_windows()

    def stop_plugin(self):
        if self.gui:
            self.gui.term()
            self.gui = None
