# -*- coding: utf-8 -*-
import logging

from idaapi import plugin_t, PLUGIN_SKIP, PLUGIN_OK, PLUGIN_KEEP, IDA_SDK_VERSION

from revengai.manager import RevEngState


logger = logging.getLogger("REAI")


class RevEngPlugin(plugin_t):
    # Variables required by IDA
    flags = 0  # Normal plugin
    wanted_hotkey = "Ctrl-Shift-R"
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

        logger.info("%s reloading...", self.wanted_name)

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
    return RevEngPlugin()
