from hashlib import sha256
import idaapi
import ida_ida
import ida_kernwin
import ida_nalt
from binascii import hexlify
from revengai.handler import (
    UploadBinaryHandler,
    # ExplainFunctionHandler,
    RenameFileHandler,
)
from revengai.gui.upload_view import UploadView
from revengai.api import Endpoint
from revengai.configuration import Configuration


class ContextHook(idaapi.UI_Hooks):
    """
    This deals with adding buttons to the context menu (right-click menu) within
    the various view, pseudocode, disassembly and proximity view
    """

    def __init__(
        self,
        form: "MainForm",
        endpoint: Endpoint,
        configuration: Configuration,
        upload_view: UploadView,
    ):
        ida_kernwin.UI_Hooks.__init__(self)
        self._endpoint = endpoint
        self.upload_view = upload_view
        self.plugin_configuration = configuration
        self._form = form

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None) -> None:
        """
        Callback when use right clicks - we need to check what view the right-click is occuring
        in and whether we want to add our buttons to the menu.

        NOTE - This menu ONLY shows when there is a valid configuration present either persisted
        or entered by the user.
        """
        t = idaapi.get_widget_type(widget)
        if (
            t == idaapi.BWN_PSEUDOCODE or t == idaapi.BWN_DISASM
        ) and self.plugin_configuration.is_valid():
            current_file_info = {"hash": hexlify(ida_nalt.retrieve_input_file_sha256()).decode()}
            CONTEXT_MENU = "RevEng.AI/"

            # The upload handler needs the current upload view to add the
            # file to the list of uploaded files
            action_name_upload = idaapi.action_desc_t(
                None,
                "Upload...",
                UploadBinaryHandler(self.upload_view, self._endpoint),
            )

            action_name_rename_file = idaapi.action_desc_t(
                None,
                "Rename Function... / Analyse...",
                RenameFileHandler(self.plugin_configuration, self._endpoint),
            )

            #
            # TODO - enable same status window from context-menu as well
            #
            # action_name_status_file = idaapi.action_desc_t(
            #     None,
            #     "Status...",
            # )

            # TODO - broken
            # action_name_explain_func = idaapi.action_desc_t(
            #     None, "Explain...", ExplainFunctionHandler(self._endpoint)
            # )

            idaapi.attach_dynamic_action_to_popup(
                widget,
                popup_handle,
                action_name_upload,
                CONTEXT_MENU,
                idaapi.SETMENU_INS,
            )

            idaapi.attach_dynamic_action_to_popup(
                widget, popup_handle, action_name_rename_file, CONTEXT_MENU, idaapi.SETMENU_INS
            )

            # TODO - broken
            # idaapi.attach_dynamic_action_to_popup(
            #     widget,
            #     popup_handle,
            #     action_name_explain_func,
            #     CONTEXT_MENU,
            #     idaapi.SETMENU_INS,
            # )
