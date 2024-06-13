# -*- coding: utf-8 -*-
import abc
import logging

from idc import get_input_file_path
from idaapi import CH_CAN_DEL, CH_CAN_EDIT, CH_CAN_REFRESH, CH_MODAL, \
    CH_NO_STATUS_BAR, CHCOL_DEC, CHCOL_PLAIN, CH_NO_FILTER, Choose, Form, MFF_FAST, execute_sync, open_url

from PyQt5.QtWidgets import QMessageBox

from itertools import filterfalse

from reait.api import RE_delete

from revengai import __version__
from revengai.conf import RevEngConfiguration
from revengai.gui import Requests
from revengai.manager import RevEngState
from revengai.misc.qtutils import inthread


logger = logging.getLogger("REAI")


class Dialog(object):
    @staticmethod
    def showInfo(title: str, message: str) -> None:
        execute_sync(Requests.MsgBox(title, message, -1), MFF_FAST)

    @staticmethod
    def showError(title: str, message: str) -> None:
        execute_sync(Requests.MsgBox(title, message, QMessageBox.Warning), MFF_FAST)


class BaseForm(Form):
    __metaclass__ = abc.ABCMeta

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


class StatusForm(BaseForm):
    class StatusFormChooser(Choose):
        def __init__(self, title: str, state: RevEngState, items: list,
                     flags: int = CH_CAN_DEL | CH_CAN_EDIT | CH_CAN_REFRESH | CH_MODAL | CH_NO_STATUS_BAR | CH_NO_FILTER):
            Choose.__init__(self, title=title, flags=flags, embedded=True, icon=state.icon_id,
                            popup_names=["", "Delete Analysis", "View Analysis Report", "Select as Current Analysis"],
                            cols=[["Binary Name", 30 | CHCOL_PLAIN],
                                  ["Analysis ID", 5 | CHCOL_DEC],
                                  ["Status", 6 | CHCOL_PLAIN],
                                  ["Submitted Date", 13 | CHCOL_PLAIN],
                                  ["Model Name", 12 | CHCOL_PLAIN],])

            self.state = state
            self.items = items
            self.fpath = get_input_file_path()

        def show(self) -> int:
            return self.Show((self.flags & CH_MODAL) == CH_MODAL)

        def GetItems(self) -> list:
            return self.items

        def SetItems(self, items: list) -> None:
            self.items = [] if items is None else items

        def OnGetLine(self, sel) -> any:
            return self.items[sel]

        def OnGetSize(self) -> int:
            return len(self.items)

        def OnGetIcon(self, sel):
            pos = sel if isinstance(sel, int) else sel[0]

            if int(self.OnGetLine(pos)[1]) == self.state.config.get("binary_id"):
                return self.icon
            if self.OnGetLine(pos)[2] == "Error":
                return 62
            elif self.OnGetLine(pos)[2] == "Complete":
                return 61
            return 60

        def OnEditLine(self, sel) -> None:
            pos = sel if isinstance(sel, int) else sel[0]

            if pos >= 0:
                logger.info("Analysis Report ID %s | %s",
                            self.OnGetLine(pos)[1], self.OnGetLine(pos)[0])

                url = f"{self.state.config.PORTAL}/analyses/"

                if self.OnGetLine(pos)[2] == "Complete":
                    url += self.OnGetLine(pos)[1]

                open_url(url)

        def OnRefresh(self, sel) -> None:
            pos = sel if isinstance(sel, int) else sel[0]

            if 0 <= pos < self.OnGetSize() and self.OnGetLine(pos)[2] != "Error":
                binary_id = int(self.OnGetLine(pos)[1])

                logger.info("Selecting analysis ID %d as current", binary_id)

                self.state.config.set("binary_id", binary_id)

        def OnDeleteLine(self, sel) -> tuple:
            if isinstance(sel, int):
                sel = [sel]

            for idx in sel:
                binary_id = int(self.OnGetLine(idx)[1])
                logger.info("Delete analysis ID %d", binary_id)

                inthread(RE_delete, self.fpath, binary_id)

                self.state.config.database.delete_analysis(binary_id)

                if self.state.config.get("binary_id", 0) == binary_id:
                    self.state.config.init_current_analysis()

            self.items = [*filterfalse(lambda i: i in (self.OnGetLine(j) for j in sel), self.items)]
            return Choose.ALL_CHANGED, sel

    def __init__(self, state: RevEngState, items: list):
        self.invert = False
        self.EChooser = StatusForm.StatusFormChooser("", state, items)

        Form.__init__(self,
                      r"""BUTTON CANCEL NONE
RevEng.AI Toolkit: Binary Analyses History

{FormChangeCb}
View and manage analyses of the current binary:
<:{cEChooser}>
""", {
                          "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
                          "cEChooser": Form.EmbeddedChooserControl(self.EChooser),
                      })


class UploadBinaryForm(BaseForm):
    def __init__(self, state: RevEngState):
        self.invert = False

        try:
            index = state.config.MODELS.index(state.config.get("model"))
        except ValueError:
            index = 0

        Form.__init__(self,
                      r"""BUTTON YES* Analyse
RevEng.AI Toolkit: Upload Binary for Analysis

{FormChangeCb}
Choose your options for binary analysis

<#Debugging information for uploaded binary#~D~ebug Info or PDB\::{iDebugFile}>
<#Add custom tags to your file#~C~ustom Tags\:      :{iTags}>
<#Model that you want the file to be analysed by#AI ~M~odel\:         :{iModel}>

Privacy:
    <#You are the only one able to access this file#Private to you:{rOptPrivate}>
    <#Everyone will be able to search against this file#Public access:{rOptPublic}>{iScope}>
""", {
                          "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
                          "iScope": Form.RadGroupControl(("rOptPrivate", "rOptPublic",)),
                          "iDebugFile": Form.FileInput(swidth=40, open=True),
                          "iTags": Form.StringInput(swidth=40, tp=Form.FT_ASCII),
                          "iModel": Form.DropdownListControl(swidth=40, selval=index, items=state.config.MODELS)
                      })


class AboutForm(BaseForm):
    def __init__(self):
        self.invert = False

        Form.__init__(self,
                      r"""BUTTON YES* Open Reveng.AI Website
RevEng.AI Toolkit: About

{FormChangeCb}
RevEng.AI Toolkit IDA plugin v%s.

RevEng.AI Toolkit is released under the GPL v2.
Find more info at https://reveng.ai/
""" % __version__, {
                          "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
                      })

    def OnFormChange(self, fid):
        if fid == -2:   # Goto homepage
            open_url("https://reveng.ai/")
        return super().OnFormChange(fid)


class UpdateForm(BaseForm):
    def __init__(self, message: str):
        self.invert = False

        Form.__init__(self,
                      r"""BUTTON YES* Open Reveng.AI Website
RevEng.AI Toolkit: Check for Update

{FormChangeCb}
Your RevEng.AI Toolkit IDA plugin is v%s.
%s
""" % (__version__, message), {
                          "FormChangeCb": Form.FormChangeCb(self.OnFormChange),
                      })

    def OnFormChange(self, fid):
        if fid == -2:  # Goto homepage
            open_url(f"{RevEngConfiguration.PORTAL}/integrations")
        return super().OnFormChange(fid)
