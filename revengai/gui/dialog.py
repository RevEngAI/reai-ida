# -*- coding: utf-8 -*-

from idc import get_input_file_path
from idaapi import CH_CAN_DEL, CH_MULTI, CH_MODAL, CH_NO_STATUS_BAR, CHCOL_DEC, CHCOL_PLAIN, Choose, Form

from PyQt5.QtWidgets import QMessageBox

from qtutils import inthread
from itertools import filterfalse

from reait.api import RE_delete

from revengai.manager import RevEngState


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
                     flags: int = CH_CAN_DEL | CH_MULTI | CH_MODAL | CH_NO_STATUS_BAR):
            Choose.__init__(self, title=title, flags=flags, embedded=True,
                            cols=[["File Name", 20 | CHCOL_PLAIN],
                                  ["Analysis ID", 6 | CHCOL_DEC],
                                  ["Status", 5 | CHCOL_PLAIN],
                                  ["Submitted Date", 16 | CHCOL_PLAIN]])
            self.state = state
            self.items = items
            self.fpath = get_input_file_path()

        def OnGetLine(self, n) -> any:
            return self.items[n]

        def OnGetSize(self) -> int:
            return len(self.items)

        def OnDeleteLine(self, sel) -> tuple:
            for idx in sel:
                inthread(RE_delete, self.fpath, self.OnGetLine(idx)[1])

                if self.state.config.get("binary_id") == self.OnGetLine(idx)[1]:
                    self.state.config.set("binary_id")
                self.state.config.database.delete_analysis(self.OnGetLine(idx)[1])

            self.items = [*filterfalse(lambda i: i in (self.OnGetLine(j) for j in sel), self.items)]
            return Choose.ALL_CHANGED, sel[0]

    def __init__(self, state: RevEngState, items: list):
        self.invert = False
        Form.__init__(self,
                      r"""STARTITEM 0
BUTTON CANCEL NONE
Binary Analysis History
      
{OnChangeFormCallback}
<:{History}>
""", {
                          "OnChangeFormCallback": Form.FormChangeCb(self.OnFormChange),
                          "History": Form.EmbeddedChooserControl(StatusForm.StatusFormChooser("", state, items))
                      })

    def OnFormChange(self, fid) -> int:
        """
        Triggered when an event occurs on form
        """
        return 1
