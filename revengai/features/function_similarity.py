# -*- coding: utf-8 -*-
import logging

import idc
from PyQt5.QtWidgets import QMenu
from idaapi import ASKBTN_YES

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIntValidator, QCursor
from ida_nalt import get_imagebase

from requests import Response, HTTPError

from reait.api import re_binary_id, RE_nearest_symbols_batch

from revengai.api import RE_quick_search
from revengai.features import BaseDialog
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.misc.utils import IDAUtils
from revengai.misc.qtutils import inthread, inmain
from revengai.models.table_model import RevEngTableModel
from revengai.ui.function_similarity_panel import Ui_FunctionSimilarityPanel


logger = logging.getLogger("REAI")


class FunctionSimilarityDialog(BaseDialog):
    def __init__(self, state: RevEngState, fpath: str):
        BaseDialog.__init__(self, state, fpath)

        start_addr = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)

        if start_addr is not idc.BADADDR:
            self.v_addr = start_addr - get_imagebase()
        else:
            self.v_addr = 0
            logger.error("Pointer location not in valid function")
            Dialog.showError("Find Similar Functions", "Cursor position not in a function.")

        self.ui = Ui_FunctionSimilarityPanel()
        self.ui.setupUi(self)

        self.ui.renameButton.setEnabled(False)

        self.ui.lineEdit.setValidator(QIntValidator(1, 256, self))
        self.ui.tableView.setModel(RevEngTableModel(data=[], parent=self,
                                                    header=["Function Name", "Confidence", "From",]))

        self.ui.tableView.customContextMenuRequested.connect(self._table_menu)

        self.ui.fetchButton.setFocus()
        self.ui.fetchButton.clicked.connect(self._fetch)
        self.ui.renameButton.clicked.connect(self._rename_symbol)

        self._similarities = {}

    def showEvent(self, event):
        super(FunctionSimilarityDialog, self).showEvent(event)

        inthread(self._quick_search)

    def closeEvent(self, event):
        super(FunctionSimilarityDialog, self).closeEvent(event)

        self._similarities.clear()

    def _fetch(self):
        if self.v_addr > 0:
            inthread(self._load, self.ui.comboBox.currentData(),
                     (100 - int(self.ui.doubleSpinBox.text().replace("%", "").replace(",", "."))) / 100.0)

    def _load(self, collections, distance):
        try:
            self._similarities.clear()

            model = inmain(self.ui.tableView.model)
            
            inmain(model.fill_table, [])
            inmain(self.ui.fetchButton.setEnabled, False)
            inmain(self.ui.renameButton.setEnabled, False)
            inmain(self.ui.progressBar.setProperty, "value", 25)

            if not self.analyzed_functions or len(self.analyzed_functions) == 0:
                self._get_analyze_functions()

            function_id = self.analyzed_functions.get(self.v_addr, None)

            if function_id is None:
                inmain(idc.warning, "No similar functions found.")
                logger.error("No similar functions found for: %s",
                             inmain(idc.get_func_name, self.v_addr))
                return

            inmain(self.ui.progressBar.setProperty, "value", 50)

            res = RE_nearest_symbols_batch(function_ids=[function_id,],
                                           nns=int(inmain(self.ui.lineEdit.text)),
                                           ignore_hashes=[re_binary_id(self.path),],
                                           distance=distance, collections=collections,
                                           debug_enabled=inmain(self.ui.checkBox.isChecked))

            inmain(self.ui.progressBar.setProperty, "value", 75)

            data = []
            for function_id, functions in res.json()["function_matches"].items():
                if function_id == str(function_id):
                    for func_id, function in functions.items():
                        self._similarities[f"{function['function_name']}_"
                                           f"{function['binary_name']}"] = func_id
                        data.append((function["function_name"],
                                     str(function["confidence"]),
                                     function["binary_name"],))

            inmain(model.fill_table, data)
            inmain(self.ui.tableView.resizeColumnsToContents)
            inmain(self.ui.progressBar.setProperty, "value", 100)
            inmain(self.ui.renameButton.setEnabled, len(data) > 0)

            if len(data) == 0:
                inmain(idc.warning, "No similar functions found.")
                logger.error("No similar functions found for: %s",
                             inmain(idc.get_func_name, inmain(idc.here)))
        except HTTPError as e:
            inmain(Dialog.showError, "Auto Analysis", e.response.json()["error"])
        finally:
            inmain(self.ui.fetchButton.setEnabled, True)
            inmain(self.ui.progressBar.setProperty, "value", 0)

    def _rename_symbol(self):
        rows = self.ui.tableView.selectionModel().selectedRows(column=0)

        if len(rows) > 0:
            new_func_name = self.ui.tableView.model().data(rows[0], Qt.DisplayRole)

            if not IDAUtils.set_name(self.v_addr, new_func_name):
                Dialog.showError("Rename Function Error", "Symbol already exists.")
            else:
                inthread(self._set_function_renamed, self.v_addr, new_func_name)

                if False and ASKBTN_YES == idc.ask_yn(ASKBTN_YES,
                                                      "Do you also want to rename the function arguments?"):
                    from revengai.actions import function_signature

                    function_signature(self.state, self.v_addr)

    def _quick_search(self):
        try:
            inmain(self.ui.comboBox.clear)

            res: Response = RE_quick_search(self.state.config.get("model"))

            collections = set()

            for collection in res.json()["collections"]:
                collections.add(collection["collection_name"])

            if len(collections) == 0:
                inmain(self.ui.label.setVisible, False)
                inmain(self.ui.comboBox.setVisible, False)
            else:
                inmain(self.ui.comboBox.addItems, collections)
                inmain(self.ui.comboBox.setCurrentIndex, -1)
        except HTTPError as e:
            inmain(self.ui.label.setVisible, False)
            inmain(self.ui.comboBox.setVisible, False)
            logger.error("Getting collections failed: %s", e)

    def _table_menu(self) -> None:
        if self.ui.tableView.selectedIndexes() and self.ui.renameButton.isEnabled():
            menu = QMenu()
            renameAction = menu.addAction(self.ui.renameButton.text())
            renameAction.triggered.connect(self._rename_symbol)

            func_id = self._similarities.get(f"{self.ui.tableView.selectedIndexes()[0].data()}_"
                                             f"{self.ui.tableView.selectedIndexes()[2].data()}")

            if func_id:
                breakdownAction = menu.addAction("View Function Breakdown")
                breakdownAction.triggered.connect(lambda: self._function_breakdown(func_id))

            menu.exec_(QCursor.pos())

    def _function_breakdown(self, func_id: int) -> None:
        from webbrowser import open_new_tab

        open_new_tab(f"http://dashboard.local/function/{func_id}")
