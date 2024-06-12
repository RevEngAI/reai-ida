# -*- coding: utf-8 -*-
import logging

# Third-Party Python Modules
required_modules_loaded = True
try:
    import reait.api

    from requests.packages.urllib3 import disable_warnings
    from requests.packages.urllib3.exceptions import InsecureRequestWarning, NotOpenSSLWarning

    disable_warnings(NotOpenSSLWarning)

    # Workaround to suppress warnings about SSL certificates
    disable_warnings(InsecureRequestWarning)
except ImportError:
    required_modules_loaded &= False

    from idc import msg

    msg("RevEng.AI Toolkit requires Python module reait\n")


from idaapi import execute_ui_requests, plugin_t, PLUGIN_SKIP, PLUGIN_OK, PLUGIN_KEEP, IDA_SDK_VERSION

from revengai.gui import Requests
from revengai.manager import RevEngState


logger = logging.getLogger("REAI")


class RevEngPlugin(plugin_t):
    # Variables required by IDA
    flags = 0  # Normal plugin
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

        logger.info("%s plugin starts", self.wanted_name)

        if self.state.config.auto_start:
            self.run()
            return PLUGIN_KEEP
        return PLUGIN_OK

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


def PLUGIN_ENTRY():
    global required_modules_loaded

    if required_modules_loaded:
        return RevEngPlugin()

    execute_ui_requests((Requests.MsgBox(RevEngPlugin.wanted_name,
                                         f"[{RevEngPlugin.wanted_name}] Unable to load all required modules."),))
    return None
