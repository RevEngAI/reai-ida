# -*- coding: utf-8 -*-
import logging

from idc import get_inf_attr, APPT_LIBRARY, APPT_PROGRAM, INF_APPTYPE, INF_FILETYPE, \
    FT_ELF, FT_PE, FT_MACHO, FT_EXE, FT_BIN
from idaapi import execute_ui_requests, plugin_t, IDA_SDK_VERSION, PLUGIN_SKIP, PLUGIN_OK, PLUGIN_KEEP, PLUGIN_HIDE

from revengai.gui import Requests

# Third-Party Python Modules
required_modules_loaded = True
try:
    import reait.api

    from revengai.manager import RevEngState

    from requests.packages.urllib3 import disable_warnings
    from requests.packages.urllib3.exceptions import InsecureRequestWarning

    # Workaround to suppress warnings about SSL certificates
    disable_warnings(InsecureRequestWarning)
except ImportError:
    required_modules_loaded &= False

    from idc import msg

    msg("[!] RevEng.AI Toolkit requires the Python module called 'reait'.\n")


logger = logging.getLogger("REAI")


class RevEngPlugin(plugin_t):
    """
    Define the plugin class itself which is returned by the PLUGIN_ENTRY method
    that scriptable plugins use to be recognized within IDA
    """
    # Variables required by IDA
    # Use the HIDE to avoid the entry in Edit/Plugins since this plugin's run() method has no functionality.
    flags = 0 if IDA_SDK_VERSION > 810 else PLUGIN_HIDE
    wanted_hotkey = ""
    wanted_name = "RevEng.AI Toolkit"
    help = f"Configure IDA plugin for {wanted_name}"
    comment = f"AI-assisted reverse engineering from {wanted_name}"

    def __init__(self):
        super(RevEngPlugin, self).__init__()

        self.initialized = False
        self.state = RevEngState()

    def init(self) -> int:
        """
        Called when the plugin is initialised.
        """
        if IDA_SDK_VERSION < 800:
            logger.warning("%s support 8.X IDA => skipping...", self.wanted_name)
            return PLUGIN_SKIP
        elif get_inf_attr(INF_APPTYPE) not in (APPT_LIBRARY, APPT_PROGRAM,) and \
                get_inf_attr(INF_FILETYPE) not in (FT_BIN, FT_PE, FT_ELF, FT_EXE, FT_MACHO,):
            logger.warning("%s supports PE, ELF, RAW, EXE, DLL and Mach-O file types => skipping...", self.wanted_name)
            return PLUGIN_SKIP

        logger.info("%s plugin starts", self.wanted_name)

        self.run()
        return PLUGIN_KEEP

    def reload_plugin(self) -> bool:
        if self.initialized:
            self.term()

        logger.info("Reloading %s...", self.wanted_name)

        self.state.start_plugin()
        self.initialized = True
        return True

    def run(self, _=None) -> bool:
        """
        Called when the plugin is invoked.
        """
        return self.reload_plugin()

    def term(self) -> None:
        """
        Called when the plugin is unloaded.
        """
        logger.info("Terminating %s...", self.wanted_name)
        if self.state is not None:
            self.state.stop_plugin()

        self.initialized = False


# The PLUGIN_ENTRY method is what IDA calls when scriptable plugins are loaded.
# It needs to return a plugin of type idaapi.plugin_t.
def PLUGIN_ENTRY():
    global required_modules_loaded

    if required_modules_loaded:
        return RevEngPlugin()

    execute_ui_requests((Requests.MsgBox(RevEngPlugin.wanted_name, "Unable to load all the required modules.", -1),))
    return None
