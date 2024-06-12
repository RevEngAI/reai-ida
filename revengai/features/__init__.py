# -*- coding: utf-8 -*-
import abc
import logging
from os.path import dirname, join

import idaapi
from PyQt5.QtCore import QRect, QTimer
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QDialog, QDesktopWidget
from reait.api import RE_functions_rename, RE_analyze_functions

from idaapi import get_imagebase

from requests import HTTPError, Response

from revengai.manager import RevEngState
from revengai.misc.icons import get_reai_icons
from revengai.misc.qtutils import inthread, inmain


logger = logging.getLogger("REAI")


class BaseDialog(QDialog):
    __metaclass__ = abc.ABCMeta

    searchDelay = 300   # Delay, in milliseconds, between the user finishing typing and the search being performed

    def __init__(self, state: RevEngState, fpath: str, analyse: bool = True):
        QDialog.__init__(self)

        self.path = fpath
        self.state = state
        self.analyse = analyse
        self.analyzed_functions = {}

        self.base_addr = get_imagebase()

        self.typing_timer = QTimer(self)
        self.typing_timer.setSingleShot(True)   # Ensure the timer will fire only once after it was started
        self.typing_timer.timeout.connect(self._filter_collections)

        self.setModal(True)
        self.setWindowIcon(QIcon(join(dirname(__file__), "..", "resources", "favicon.png")))

    def showEvent(self, event):
        super(BaseDialog, self).showEvent(event)

        screen: QRect = QDesktopWidget().screenGeometry()

        # Center the dialog to screen
        self.move(screen.width() // 2 - self.width() // 2,
                  screen.height() // 2 - self.height() // 2)

        if self.analyse:
            inthread(self._get_analyze_functions)

    def closeEvent(self, event):
        super(BaseDialog, self).closeEvent(event)

        self.analyzed_functions.clear()

    def _get_analyze_functions(self) -> None:
        try:
            res: Response = RE_analyze_functions(self.path, self.state.config.get("binary_id", 0))

            for function in res.json()["functions"]:
                self.analyzed_functions[function["function_vaddr"]] = function["function_id"]
        except HTTPError as e:
            logger.error("Error getting analysed functions: %s",
                         e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience."))

    def _set_function_renamed(self, func_addr: int, new_func_name: str, func_id: int = 0) -> None:
        if not func_id:
            func_id = self._get_function_id(func_addr)

        if func_id:
            try:
                res: Response = RE_functions_rename(func_id, new_func_name)

                logger.info(res.json()["msg"])
            except HTTPError as e:
                error = e.response.json().get("error", "An unexpected error occurred. Sorry for the inconvenience.")
                logger.error("Failed to rename functionId %d by '%s'. %s", func_id, new_func_name, error)

                inmain(idaapi.warning, error)
        else:
            logger.error('Not found functionId at address: 0x%X.', func_addr)

    def _function_breakdown(self, func_id: int) -> None:
        # Prevent circular import
        from revengai.actions import function_breakdown

        function_breakdown(self.state, func_id)

    def _get_function_id(self, func_addr: int) -> int:
        return self.analyzed_functions.get(func_addr, 0)

    def _filter_collections(self):
        pass
