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
from revengai.misc.utils import IDAUtils
from enum import Enum


logger = logging.getLogger("REAI")


class SyncOp(Enum):
    CREATE = 1
    UPDATE = 2
    DELETE = 3


class SyncFunctionsDialog(BaseDialog):
    def __init__(self, state: RevEngState, fpath: str, data: list):
        BaseDialog.__init__(self, state, fpath, False)

        self.data = data

        self.ui = Ui_SyncFunctionsPanel()
        self.ui.setupUi(self)

        self.ui.functionsList.customContextMenuRequested.connect(
            self._table_menu)
        self.ui.functionsList.horizontalHeader().setDefaultAlignment(
            Qt.AlignLeft
        )
        self.ui.functionsList.setModel(
            RevEngCheckableTableModel(
                data=self.data,
                parent=self,
                columns=[0],
                header=[
                    "",
                    "New Name",
                    "Old Name",
                    "Function Address",
                    "Update Location",
                    "Reason",
                ],
            )
        )

        self.ui.syncButton.setFocus()
        self.ui.syncButton.clicked.connect(self._synchronise)
        self.ui.cancelButton.clicked.connect(self._cancel)
        self.ui.selectAll.stateChanged.connect(self._select_all)
        self.ui.description.setText(
            f"Synchronise <i>{basename(fpath)}</i>"
            " and RevEng.AI platform for each function name that differs."
        )

    def showEvent(self, event):
        super().showEvent(event)

        width: int = self.ui.functionsList.width()

        self.ui.functionsList.setColumnWidth(0, round(width * 0.04))
        self.ui.functionsList.setColumnWidth(1, round(width * 0.2))
        self.ui.functionsList.setColumnWidth(2, round(width * 0.2))
        self.ui.functionsList.setColumnWidth(3, round(width * 0.1))
        self.ui.functionsList.setColumnWidth(4, round(width * 0.1))
        self.ui.functionsList.setColumnWidth(5, round(width * 0.75))

    def _cancel(self) -> None:
        self.close()

    def _synchronise(self) -> None:
        if not any(
                isinstance(
                    row[0], CheckableItem) and row[0].checkState == Qt.Checked
                for row in self.ui.functionsList.model().get_datas()
        ):
            Dialog.showInfo(
                "Synchronise Functions",
                "Select at least one function to be synchronised.",
            )
        else:
            remote_update_functions = {}
            local_update_functions = []
            create_functions = []
            rows = self.ui.functionsList.model().get_datas()
            for row_item in rows:
                if (
                        isinstance(row_item[0], CheckableItem)
                        and row_item[0].checkState == Qt.Checked
                ):
                    func_data = row_item[0].data
                    op = func_data["op"]

                    if op == SyncOp.UPDATE and row_item[4] == "REMOTE":
                        remote_update_functions[
                            func_data["function_id"]
                        ] = func_data["function_name"]
                    elif op == SyncOp.UPDATE and row_item[4] == "LOCAL":
                        local_update_functions.append(
                            {
                                "function_data": func_data,
                                "new_name": row_item[1],
                            }
                        )
                    elif op == SyncOp.CREATE:
                        create_functions.append(
                            {
                                "function_data": func_data,
                                "new_name": row_item[1],
                            }
                        )
            if len(remote_update_functions) > 0:
                inthread(self._batch_function_rename, remote_update_functions)

            if len(local_update_functions) > 0:
                for el in local_update_functions:
                    self._update_local_function(
                        el["function_data"],
                        el["new_name"]
                    )

            if len(create_functions) > 0:
                for el in create_functions:
                    self._create_function(
                        el["function_data"],
                        el["new_name"]
                    )

            Dialog.showInfo(
                "Synchronise Functions",
                "Function synchronisation is now complete.",
            )
            # automatically close the dialog
            self.close()

    def _select_all(self) -> None:
        checkState = Qt.Checked if self.ui.selectAll.isChecked() \
            else Qt.Unchecked

        for row_item in self.ui.functionsList.model().get_datas():
            if isinstance(row_item[0], CheckableItem):
                row_item[0].checkState = checkState

        self.ui.functionsList.model().layoutChanged.emit()

    def _table_menu(self) -> None:
        rows = sorted(
            set(index.row()
                for index in self.ui.functionsList.selectedIndexes())
        )
        selected = self.ui.functionsList.model().get_data(rows[0])

        if selected and isinstance(selected[0], CheckableItem):
            menu = QMenu()
            syncAction = menu.addAction(self.ui.syncButton.text())
            syncAction.triggered.connect(
                lambda: self._rename_symbol(
                    selected[0].data,
                    selected[1],
                    selected[4]
                ))

            jumpToAction = menu.addAction("Jump to Function")
            jumpToAction.triggered.connect(
                lambda: idc.jumpto(selected[0].data["function_vaddr"])
            )

            func_id = selected[0].data["function_id"]
            breakdownAction = menu.addAction("View Function Breakdown")
            breakdownAction.triggered.connect(
                lambda: self._function_breakdown(func_id))

            # summariesAction = menu.addAction("Generate AI Summaries")
            # summariesAction.triggered.connect(
            # lambda: self._generate_summaries(func_id))

            menu.exec_(QCursor.pos())

    def _delete_function(self, function_data) -> None:
        # Prevent circular import
        logger.warning(
            "Function deletion is not implemented yet. "
        )

    def _create_function(self, function_data, new_name: str) -> None:
        # Prevent circular import
        logger.warning(
            "Function creation is not implemented yet. "
            "Please create a function manually at "
            f"{hex(function_data['function_vaddr'] + self.base_addr)} "
            f"with the name {new_name}."
        )

    def _update_local_function(self, function_data, new_name: str) -> None:
        if IDAUtils.set_name(
            function_data["function_vaddr"] + self.base_addr,
            new_name,
        ):
            logger.info(
                "Renamed function at 0x%X to %s",
                function_data["function_vaddr"],
                new_name,
            )
        else:
            # update failed there could be multiple reasons:
            # - function already exists
            # etc...
            logger.error(
                "Failed to rename function at 0x%X to %s",
                function_data["function_vaddr"],
                new_name,
            )

    def _update_remote_function(self, function_data, new_name: str) -> None:
        inthread(
            self._function_rename,
            function_data["function_vaddr"],
            new_name,
            function_data["function_id"],
        )

    def _rename_symbol(self, function_data, new_name: str, where: str) -> None:
        # first check OP
        op = function_data["op"]
        match op:
            case SyncOp.CREATE:
                self._create_function(function_data, new_name)
            case SyncOp.UPDATE:
                if where == "REMOTE":
                    self._update_remote_function(function_data, new_name)
                elif where == "LOCAL":
                    self._update_local_function(function_data, new_name)
            case SyncOp.DELETE:
                self._delete_function(function_data)
