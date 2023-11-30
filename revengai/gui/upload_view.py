import ida_nalt
from binascii import hexlify
from typing import List
from hashlib import sha256
from pathlib import Path
from PyQt5 import QtWidgets, QtCore
from idaapi import warning
from revengai.logger import plugin_logger
from revengai.api import Endpoint
from revengai.configuration import Configuration


class UploadView:
    def __init__(self, configuration: Configuration, endpoint: Endpoint) -> None:
        self._parent = None  # ref to parent widget
        self._endpoint = endpoint
        self._configuration = configuration
        self._table: QtWidgets.QTableWidget = None

    def insert_entry(self, fp: str) -> None:
        # NOTE - success code checked so add it
        # TODO - might be better to remove this completely and directly callto configuration
        # from event handler
        hash = hexlify(ida_nalt.retrieve_input_file_sha256()).decode()
        plugin_logger.debug(f"file hash {hash}")
        self._configuration.add_file_tracking(
            hash,
            {"file_path": Path(fp).name, "hash": hash},
        )

    def action_delete(self) -> None:
        # use end point to send a request to REST to delete the file from processing
        name, status, hash = [
            self._table.item(self._table.currentRow(), column).text()
            for column in range(self._table.columnCount())
        ]

        plugin_logger.info(f"current hash selected {hash}")
        bin_id = self._endpoint.get_id(hash)
        id = self._endpoint.get_id(hash)
        if id:
            js_del, res_del = self._endpoint.delete(id)
            if res_del.status_code == 200:
                # remove the row and delete file tracking
                self._table.removeRow(self._table.currentRow())
                self._configuration.remove_file_tracking(hash)
            else:
                warning(f"failed to delete file - see log")

    def action_stop_tracking(self) -> None:
        # just remove the entry from the portion of the configuration
        # No way to get all items from a particular row within the table, really??
        name, status, hash = [
            self._table.item(self._table.currentRow(), column).text()
            for column in range(self._table.columnCount())
        ]

        plugin_logger.info(f"current hash selected {hash}")

        # use hash to remove from tracked files list
        self._configuration.remove_file_tracking(hash)

        # remove from the table too now
        self._table.removeRow(self._table.currentRow())

    def draw_context_menu(self, pos) -> None:
        # highlight row
        for col in range(self._table.columnCount()):
            item = self._table.item(self._table.currentRow(), col)
            if item:
                item.setSelected(True)

        plugin_logger.info(f"current row selected {self._table.currentRow()}")

        # Create menu
        menu = QtWidgets.QMenu(self._table)

        action_stop_tracking = QtWidgets.QAction("Stop tracking..")
        action_delete = QtWidgets.QAction("Delete..")

        # register callbacks
        action_stop_tracking.triggered.connect(self.action_stop_tracking)
        action_delete.triggered.connect(self.action_delete)

        menu.addAction(action_stop_tracking)
        menu.addAction(action_delete)

        # Draw the widget where mouse is
        global_pos = self._table.mapToGlobal(pos)
        menu.exec_(global_pos)

    def view(self) -> QtWidgets.QWidget:
        container = QtWidgets.QGroupBox("Uploads")
        layout = QtWidgets.QVBoxLayout()
        self._table = QtWidgets.QTableWidget()
        self._table.setColumnCount(3)
        self._table.setShowGrid(False)
        self._table.setHorizontalHeaderLabels(["File", "Upload Status", "SHA256"])
        self._table.setSelectionBehavior(
            QtWidgets.QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)

        self._table.setRowCount(self._configuration.get_tracked_files_number())
        plugin_logger.debug(f"{self._configuration.get_current_files()}")

        # fill table with data using tracked_files
        track_files = self._configuration.get_current_files()
        if track_files is not None:
            for idc, k in enumerate(track_files):
                plugin_logger.info(f"adding {track_files[k]} at index {idc}")
                name = QtWidgets.QTableWidgetItem(
                    f"{track_files[k]['file_path']}"
                )  # fp
                status = QtWidgets.QTableWidgetItem(f"")  # status
                hash = QtWidgets.QTableWidgetItem(f"{k}")  # hash
                self._table.setItem(idc, 0, name)
                self._table.setItem(idc, 1, status)
                self._table.setItem(idc, 2, hash)

        # set the whole table to uneditable
        self._table.setEditTriggers(QtWidgets.QTableWidget.EditTrigger.NoEditTriggers)

        layout.addWidget(self._table)
        container.setLayout(layout)

        for r in range(self._table.rowCount()):
            self._table.setRowHeight(r, 8)

        # set context callbacks
        self._table.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self.draw_context_menu)
        return container
