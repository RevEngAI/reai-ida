import ida_nalt
from binascii import hexlify
import ida_kernwin
import idaapi
from typing import List
from hashlib import sha256
from pathlib import Path
from PyQt5 import QtWidgets, QtCore
from idaapi import warning
from revengai.logger import plugin_logger
from revengai.api import Endpoint
from revengai.configuration import Configuration
from revengai.gui.dialog import Dialog

# from revengai.gui.rename_function_form import busy_form_t


class StatusForm(ida_kernwin.Form):
    class StatusFormChooser(ida_kernwin.Choose):
        def __init__(
            self,
            title,
            items,
            flags=ida_kernwin.Choose.CH_MULTI,
        ):
            ida_kernwin.Choose.__init__(
                self,
                title,
                [
                    ["File name", 20],
                    ["analysis id", 5],
                    ["status", 5],
                    ["submitted", 5],
                ],
                flags,
                embedded=True,
                width=30,
                height=10,
            )
            self.items = items

        def OnGetLine(self, n):
            return self.items[n]

        def OnGetSize(
            self,
        ):
            n = len(self.items)
            return n

    def __init__(self, items):
        self.invert = False
        F = ida_kernwin.Form
        F.__init__(
            self,
            r"""STARTITEM 0
BUTTON Yes* Select
BUTTON CANCEL Cancel
Analysis

{OnChangeFormCallback}
<:{Analysis}>

                """,
            {
                "Analysis": F.EmbeddedChooserControl(
                    StatusForm.StatusFormChooser("Analysis Tasks", items)
                ),
                "OnChangeFormCallback": F.FormChangeCb(self.OnFormChange),
            },
        )

    def OnFormChange(self, fid):
        """
        Triggered when an event occurs on form
        """
        return 1


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

    def action_status(self) -> None:
        """
        Given a specific file (specified by sha256 file hash) -
        get all analysis carried out by the end point and
        give the user the option to select the analysis to use
        for other functionality within the plugin.
        """
        # get all the current analysis against a given file and let the user
        # select a suitable one.

        # iterate over all tracked files and attempt to retrieve all the analysis
        # per given file hash

        bin = []  # the bins returned from the endpoint
        entries = []  # the entries to be rendered in form
        for k, v in self._configuration.get_current_files().items():
            plugin_logger.info(f"requesting info for {k}")
            for b in self._endpoint.get_analysis_ids(k):
                plugin_logger.info(f"adding {b}")
                bin.append(b)

        # each bin has this data
        # {
        #     "binary_id": 17664,
        #     "binary_name": "ftp",
        #     "creation": "2024-01-04T17:38:26.909681",
        #     "model_id": 1,
        #     "model_name": "binnet-0.2-x86-linux",
        #     "owner": "root",
        #     "sha_256_hash": "f3eac8c33d664d8f1b63b450ec1fef289285b6a42fc60690d8d388ffbb3a5f23",
        #     "status": "Complete",
        #     "tags": null
        # }

        if len(bin) > 0:
            for b in bin:
                entries.append([b["binary_name"], str(b["binary_id"]), b["status"], b["creation"]])

        plugin_logger.debug(f"entries {entries}")

        # draw form to let the user select the analysis ID to use for other functionality
        f = StatusForm(entries)
        f.Compile()
        ok = f.Execute()
        if ok == 1:
            plugin_logger.debug(f"ok pressed")
            sel = f.Analysis.selection
            if sel is not None:
                # get the row selection then grab the same row from the passed in set of entires
                plugin_logger.debug(
                    f"selected {sel}, updating current context with binary_id {entries[sel[0]][1]}"
                )
                # update current context with the selected analysis id
                self._configuration.context["selected_analysis"] = entries[sel[0]][1]
            else:
                plugin_logger.debug(f"Nothing selected")
        else:
            plugin_logger.debug(f"Something else pressed {ok}")

        f.Free()

    def action_send_for_analysis(self, id) -> None:
        """
        Request that the selected file is sent for analysis
        """
        name, hash = [
            self._table.item(self._table.currentRow(), column).text()
            for column in range(self._table.columnCount())
        ]

        plugin_logger.info(f"file name {name} hash {hash}")

        if name != ida_nalt.get_root_filename():
            warning(f"Please select the file you are currently viewing")
            return

        with open(idaapi.get_input_file_path(), "rb") as f:
            data = f.read()
            json, resp = self._endpoint.analyze(name, hash)
            if resp.status_code != 200:
                plugin_logger.error(f"Failed to submit file for analysis {json}")
                warning(f"Failed to submit file for analysis, see log")
            else:
                # check return and show msg to user
                # assert "success" in json.keys() and json["binary_id"]  in json.keys()
                Dialog.ok_box(f"{json['success']}")

                # update current context with the selected analysis id
                self._configuration.context["selected_analysis"] = json["binary_id"]

    def draw_context_menu(self, pos) -> None:
        # highlight row
        for col in range(self._table.columnCount()):
            item = self._table.item(self._table.currentRow(), col)
            if item:
                item.setSelected(True)

        plugin_logger.info(f"current row selected {self._table.currentRow()}")

        # Create menu
        menu = QtWidgets.QMenu(self._table)

        action_status = QtWidgets.QAction("Status..")
        action_send_for_analysis = QtWidgets.QAction("Send for analysis..")

        # register callbacks
        action_status.triggered.connect(self.action_status)
        action_send_for_analysis.triggered.connect(self.action_send_for_analysis)

        menu.addAction(action_status)
        menu.addAction(action_send_for_analysis)

        # Draw the widget where mouse is
        global_pos = self._table.mapToGlobal(pos)
        menu.exec_(global_pos)

    def view(self) -> QtWidgets.QWidget:
        container = QtWidgets.QGroupBox("Uploads")
        layout = QtWidgets.QVBoxLayout()
        self._table = QtWidgets.QTableWidget()
        self._table.setColumnCount(2)
        self._table.setShowGrid(False)
        self._table.setHorizontalHeaderLabels(["file", "sha256", " current analysis id"])
        self._table.setSelectionBehavior(QtWidgets.QTableWidget.SelectionBehavior.SelectRows)
        self._table.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)

        self._table.setRowCount(self._configuration.get_tracked_files_number())
        plugin_logger.debug(f"{self._configuration.get_current_files()}")

        # fill table with data using tracked_files
        track_files = self._configuration.get_current_files()
        # tracked files are tracked like
        # {hash: {file_path: "path", hash: "hash"}}
        if track_files is not None:
            for idc, k in enumerate(track_files):
                plugin_logger.info(f"adding {track_files[k]} at index {idc}")
                name = QtWidgets.QTableWidgetItem(f"{track_files[k]['file_path']}")  # fp
                hash = QtWidgets.QTableWidgetItem(f"{k}")  # hash
                self._table.setItem(idc, 0, name)
                self._table.setItem(idc, 1, hash)

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
