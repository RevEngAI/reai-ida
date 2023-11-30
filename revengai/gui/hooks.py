import idaapi
import ida_kernwin
from revengai.handler import UploadBinaryHandler
from revengai.gui.upload_view import UploadView
from revengai.api import Endpoint
from revengai.configuration import Configuration


class ContextHook(idaapi.UI_Hooks):
    """
    NOTE: This context menu only becomes available AFTER the user
    has opened the configuration form.

    This exclusively deals with the 'Upload' on the context menu
    within the pseudo-code view.
    """

    def __init__(
        self,
        endpoint: Endpoint,
        configuration: Configuration,
        upload_view: "UploadView",
    ):
        ida_kernwin.UI_Hooks.__init__(self)
        self._endpoint = endpoint
        self.upload_view = upload_view
        self.plugin_configuration = configuration

    def finish_populating_widget_popup(self, widget, popup_handle, ctx=None) -> None:
        t = idaapi.get_widget_type(widget)
        if t == idaapi.BWN_PSEUDOCODE and self.plugin_configuration.valid:
            # add our menu to the context
            CONTEXT_MENU = "REVENGAI/"
            action_name_upload = idaapi.action_desc_t(
                None, "Upload", UploadBinaryHandler(self.upload_view, self._endpoint)
            )
            idaapi.attach_dynamic_action_to_popup(
                widget,
                popup_handle,
                action_name_upload,
                CONTEXT_MENU,
                idaapi.SETMENU_INS,
            )
