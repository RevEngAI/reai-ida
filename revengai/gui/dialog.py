# -*- coding: utf-8 -*-
import logging

from idc import get_input_file_path
from idaapi import CH_CAN_DEL, CH_CAN_EDIT, CH_MULTI, CH_MODAL, CH_NO_STATUS_BAR, CHCOL_DEC, CHCOL_PLAIN, Choose, Form

from PyQt5.QtWidgets import QMessageBox

from itertools import filterfalse

from reait.api import RE_delete
from revengai.manager import RevEngState
from revengai.misc.qtutils import inthread


logger = logging.getLogger("REAI")


class Dialog(object):
    @staticmethod
    def showInfo(title: str, message: str) -> None:
        msgBox = QMessageBox()
        msgBox.setModal(True)
        msgBox.setWindowTitle(title)
        msgBox.setText(message)
        msgBox.setIcon(QMessageBox.Information)
        msgBox.exec()

    @staticmethod
    def showError(title: str, message: str) -> None:
        msgBox = QMessageBox()
        msgBox.setModal(True)
        msgBox.setWindowTitle(title)
        msgBox.setText(message)
        msgBox.setIcon(QMessageBox.Critical)
        msgBox.exec()


class StatusForm(Form):
    class StatusFormChooser(Choose):
        def __init__(self, title: str, state: RevEngState, items: list,
                     flags: int = CH_CAN_DEL | CH_CAN_EDIT | CH_MULTI | CH_MODAL | CH_NO_STATUS_BAR):
            Choose.__init__(self, title=title, flags=flags, embedded=True, icon=state.icon_id,
                            popup_names=["", "Delete Analysis", "View Analysis Report",],
                            cols=[["Binary Name", 30 | CHCOL_PLAIN],
                                  ["Analysis ID", 6 | CHCOL_DEC],
                                  ["Status", 8 | CHCOL_PLAIN],
                                  ["Submitted Date", 14 | CHCOL_PLAIN],])
            self.state = state
            self.items = items
            self.fpath = get_input_file_path()

        def show(self) -> int:
            return self.Show((self.flags & CH_MODAL) == CH_MODAL)

        def GetItems(self) -> list:
            return self.items

        def SetItems(self, items: list) -> None:
            self.items = [] if items is None else items

        def OnGetLine(self, n) -> any:
            return self.items[n]

        def OnGetSize(self) -> int:
            return len(self.items)

        def OnEditLine(self, sel) -> None:
            logger.info("Analysis Report ID %s | %s",
                        self.OnGetLine(sel[0])[1], self.OnGetLine(sel[0])[0])

            from webbrowser import open_new_tab
            open_new_tab(f"http://dashboard.local/analyses/{self.OnGetLine(sel[0])[1]}")

        def OnDeleteLine(self, sel) -> tuple:
            for idx in sel:
                logger.info("Delete analysis %s", self.OnGetLine(idx)[1])

                inthread(RE_delete, self.fpath, self.OnGetLine(idx)[1])

                self.state.config.database.delete_analysis(self.OnGetLine(idx)[1])

                self.state.config.init_current_analysis()

            self.items = [*filterfalse(lambda i: i in (self.OnGetLine(j) for j in sel), self.items)]
            return Choose.ALL_CHANGED, sel[0]

    def __init__(self, state: RevEngState, items: list):
        self.invert = False
        self.EChooser = StatusForm.StatusFormChooser("", state, items)

        Form.__init__(self,
                      r"""BUTTON CANCEL NONE
Binary Analysis History
      
{FormChangeCb}
<:{cEChooser}>
""", {
                          "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
                          "cEChooser": Form.EmbeddedChooserControl(self.EChooser)
                      })

    def OnFormChange(self, _) -> int:
        """
        Triggered when an event occurs on form
        """
        return 1

    def Show(self) -> int:
        # Compile the form once
        if not self.Compiled():
            self.Compile()

        # Execute the form
        return self.Execute()


class UploadBinaryForm(Form):
    def __init__(self):
        self.invert = False

        Form.__init__(self,
                      r"""BUTTON YES* Analyse
Upload Binary for Analysis

{FormChangeCb}
Choose your options for binary analysis

<#Debugging information for uploaded binary#~D~ebug Info or PDB\::{iDebugFile}>
<#Add custom tags to your file#~C~ustom Tags\:      :{iTags}>

Privacy:
    <#You are the only one able to access this file#Private to you:{rOptPrivate}>
    <#Everyone will be able to search against this file#Public access:{rOptPublic}>{iScope}>
""",{
                          "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
                          "iScope": Form.RadGroupControl(("rOptPrivate", "rOptPublic",)),
                          "iDebugFile": Form.FileInput(swidth=40, open=True),
                          "iTags": Form.StringInput(swidth=40, tp=Form.FT_ASCII)
                      })

    def OnFormChange(self, _) -> int:
        """
        Triggered when an event occurs on form
        """
        return 1

    def Show(self) -> int:
        # Compile the form once
        if not self.Compiled():
            self.Compile()

        # Execute the form
        return self.Execute()
