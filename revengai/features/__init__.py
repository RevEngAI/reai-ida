# -*- coding: utf-8 -*-

import abc
import logging

from PyQt5.QtCore import QRect
from PyQt5.QtWidgets import QDialog, QDesktopWidget
from reait.api import RE_functions_rename

from requests import HTTPError, Response

from revengai.api import RE_analyze_functions
from revengai.manager import RevEngState
from revengai.misc.qtutils import inthread


logger = logging.getLogger("REAI")


class BaseDialog(QDialog):
    __metaclass__ = abc.ABCMeta

    def __init__(self, state: RevEngState, fpath: str):
        QDialog.__init__(self)

        self.path = fpath
        self.state = state
        self.analyzed_functions = {}

        state.config.init_current_analysis()

    def showEvent(self, event):
        super(BaseDialog, self).showEvent(event)

        screen: QRect = QDesktopWidget().screenGeometry()

        # Center the dialog to screen
        self.move(screen.width() // 2 - self.width() // 2,
                  screen.height() // 2 - self.height() // 2)

        inthread(self._get_analyze_functions)

    def _get_analyze_functions(self) -> None:
        try:
            res: Response = RE_analyze_functions(self.path, self.state.config.get("binary_id", 0))

            for function in res.json():
                self.analyzed_functions[function["function_vaddr"]] = function["function_id"]
        except HTTPError as e:
            if "error" in e.response.json():
                logger.error("Error getting analysed functions: %s", e.response.json()['error'])
            else:
                logger.error("Error getting analysed functions: %s", e.response.reason)

    def _set_function_renamed(self, func_addr: int, new_func_name: str) -> None:
        func_id = self.analyzed_functions.get(func_addr)

        if func_id:
            try:
                res: Response = RE_functions_rename(func_id, new_func_name)

                logger.info(res.json()['success'])
            except HTTPError as e:
                if "error" in e.response.json():
                    logger.error("Failed to rename functionId %d by %s: %s",
                                 func_id, new_func_name, e.response.json()['error'])
                else:
                    logger.error("Failed to rename functionId %d by %s: %s",
                                 func_id, new_func_name, e.response.reason)
        else:
            logger.error('Not found functionId at address: 0x%X.', func_addr)
