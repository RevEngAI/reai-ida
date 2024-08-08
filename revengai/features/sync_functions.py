# -*- coding: utf-8 -*-
import logging

from os.path import basename

import idc
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QMenu

from revengai.features import BaseDialog
from revengai.gui.dialog import Dialog
from revengai.manager import RevEngState
from revengai.misc.qtutils import inthread
from revengai.models import CheckableItem
from revengai.models.checkable_model import RevEngCheckableTableModel
from revengai.ui.auto_sync_panel import Ui_SyncFunctionsPanel


logger = logging.getLogger("REAI")


class SyncFunctionsDialog(BaseDialog):
    def __init__(self, state: RevEngState, fpath: str, data: list):
        BaseDialog.__init__(self, state, fpath, False)

        self.data = []
        for function in data:
            self.data.append((f"0x{function['function_vaddr']:08X}",
                              function["function_display"], CheckableItem(function),))

        self.ui = Ui_SyncFunctionsPanel()
        self.ui.setupUi(self)

        self.ui.functionsList.customContextMenuRequested.connect(self._table_menu)
        self.ui.functionsList.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.ui.functionsList.setModel(RevEngCheckableTableModel(data=self.data, parent=self, columns=[2],
                                                                 header=["Function Address",
                                                                         "Function Subject to Renaming", "Include",]))

        self.ui.syncButton.setFocus()
        self.ui.syncButton.clicked.connect(self._synchronise)
        self.ui.cancelButton.clicked.connect(self._cancel)
        self.ui.selectAll.stateChanged.connect(self._select_all)
        self.ui.description.setText(f"Synchronise <i>{basename(fpath)}</i> and RevEng.AI platform for each function name that differs.")

    def showEvent(self, event):
        super().showEvent(event)

        width: int = self.ui.functionsList.width()

        self.ui.functionsList.setColumnWidth(0, width * .15)
        self.ui.functionsList.setColumnWidth(1, width * .75)
        self.ui.functionsList.setColumnWidth(2, width * .1)

    def _cancel(self) -> None:
        self.close()

    def _synchronise(self) -> None:
        if not any(isinstance(row[2], CheckableItem) and row[2].checkState == Qt.Checked
                   for row in self.ui.functionsList.model().get_datas()):
            Dialog.showInfo("Synchronise Functions", "Select at least one function to be synchronised.")
        else:
            functions = {}

            for row_item in self.ui.functionsList.model().get_datas():
                if isinstance(row_item[2], CheckableItem) and row_item[2].checkState == Qt.Checked:
                    symbol = row_item[2].data

                    functions[symbol["function_id"]] = symbol["function_name"]
            if len(functions):
                inthread(self._batch_function_rename, functions)

    def _select_all(self) -> None:
        checkState = Qt.Checked if self.ui.selectAll.isChecked() else Qt.Unchecked

        for row_item in self.ui.functionsList.model().get_datas():
            if isinstance(row_item[2], CheckableItem):
                row_item[2].checkState = checkState

        self.ui.functionsList.model().layoutChanged.emit()

    def _table_menu(self) -> None:
        rows = sorted(set(index.row() for index in self.ui.functionsList.selectedIndexes()))
        selected = self.ui.functionsList.model().get_data(rows[0])

        if selected and isinstance(selected[2], CheckableItem):
            menu = QMenu()
            syncAction = menu.addAction(self.ui.syncButton.text())
            syncAction.triggered.connect(lambda: self._rename_symbol(selected[2].data))

            jumpToAction = menu.addAction("Jump to Function")
            jumpToAction.triggered.connect(lambda: idc.jumpto(selected[2].data["function_vaddr"]))

            func_id = selected[2].data["function_id"]
            breakdownAction = menu.addAction("View Function Breakdown")
            breakdownAction.triggered.connect(lambda: self._function_breakdown(func_id))

            # summariesAction = menu.addAction("Generate AI Summaries")
            # summariesAction.triggered.connect(lambda: self._generate_summaries(func_id))

            menu.exec_(QCursor.pos())

    def _rename_symbol(self, function) -> None:
        inthread(self._function_rename, function["function_vaddr"], function["function_name"], function["function_id"])
