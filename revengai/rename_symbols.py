# -*- coding: utf-8 -*-

import ida_name
import idc
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import QDialog
from ida_nalt import get_imagebase
from requests import Response, HTTPError

from reait.api import RE_embeddings, RE_nearest_symbols, binary_id
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.model.table_model import RevEngTableModel
from revengai.ui.rename_symbols_panel import Ui_RenameSymbolsPanel


class RenameSymbolsDialog(QDialog):
    def __init__(self, state: RevEngState, fpath: str):
        QDialog.__init__(self)

        self.path = fpath
        self.state = state

        start_addr = idc.get_func_attr(idc.here(), idc.FUNCATTR_START)

        if start_addr is not idc.BADADDR:
            self.v_addr = start_addr - get_imagebase()
        else:
            self.v_addr = 0
            Dialog.showError("Find Similar Functions", "Cursor position not in a function.")

        self.ui = Ui_RenameSymbolsPanel()
        self.ui.setupUi(self)

        self.ui.lineEdit.setValidator(QIntValidator(1, 256, self))
        self.ui.tableView.setModel(RevEngTableModel([], ["Function Name", "Confidence", "From"], self))

        self.ui.fetchButton.clicked.connect(self.fetch)
        self.ui.renameButton.clicked.connect(self.rename_symbol)

    def showEvent(self, event):
        super(RenameSymbolsDialog, self).showEvent(event)
        self.fetch()

    def fetch(self):
        if self.v_addr > 0:
            self._load()

    def _load(self):
        try:
            self.ui.tableView.model().updateData([])
            self.ui.fetchButton.setEnabled(False)
            self.ui.progressBar.setProperty("value", 25)

            res: Response = RE_embeddings(fpath=self.path)

            if res.status_code > 299:
                Dialog.showError("Auto Analysis",
                                 f"Auto Analysis Error: {res.json().get('error')}")
            else:
                fe = next((item for item in res.json() if item["vaddr"] == self.v_addr), None)

                if fe is None:
                    Dialog.showError("Find Similar Functions", "No similar functions found.")
                else:
                    self.ui.progressBar.setProperty("value", 50)

                    res = RE_nearest_symbols(embedding=fe["embedding"],
                                             nns=int(self.ui.lineEdit.text()),
                                             ignore_hashes=[binary_id(self.path)],
                                             model_name=self.state.config.get("model"))

                    self.ui.progressBar.setProperty("value", 75)

                    data = []
                    for item in res.json():
                        data.append([item["name"], item["distance"], item["binary_name"]])

                    self.ui.tableView.model().updateData(data)
        except HTTPError as e:
            Dialog.showError("Auto Analysis", e.response.json()["error"])
        finally:
            self.ui.fetchButton.setEnabled(True)
            self.ui.progressBar.setProperty("value", 0)

    def rename_symbol(self):
        rows = self.ui.tableView.selectionModel().selectedRows(column=0)

        if len(rows) > 0:
            if not idc.set_name(self.v_addr, self.ui.tableView.model().data(rows[0], Qt.DisplayRole),
                                ida_name.SN_FORCE | ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
                Dialog.showError("Rename Function Error", "Symbol already exists.")
