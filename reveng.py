# -*- coding: utf-8 -*-
import logging

from ida_kernwin import get_kernel_version
from idaapi import plugin_t, PLUGIN_FIX, PLUGIN_SKIP, PLUGIN_OK, PLUGIN_KEEP

from revengai.manager import RevEngState


logger = logging.getLogger("REAI")


class RevEngPlugin(plugin_t):
    # Variables required by IDA
    flags = PLUGIN_FIX  # Normal plugin
    wanted_name = "RevEng.AI Toolkit"
    help = f"Configure IDA plugin for {wanted_name}"
    comment = f"AI-assisted reverse engineering from {wanted_name}"

    def __init__(self):
        super(RevEngPlugin, self).__init__()

        self.initialized = False
        self.state = RevEngState()

    def init(self):
        kv = get_kernel_version().split(".")
        if int(kv[0]) < 8:
            logger.info("%s need IDA version >= 8.0 => skipping...", self.wanted_name)
            return PLUGIN_SKIP

        logger.info("%s initialized", self.wanted_name)

        if self.state.config.auto_start:
            self.run()
            return PLUGIN_KEEP
        return PLUGIN_OK

    def reload_plugin(self):
        if self.initialized:
            self.term()

        logger.info("%s reloading...", self.wanted_name)

        self.state.start_plugin()
        self.initialized = True

    def run(self, args=None):
        self.reload_plugin()

    def term(self):
        logger.info("Terminating %s...", self.wanted_name)
        if self.state is not None:
            self.state.stop_plugin()

        self.initialized = False


def PLUGIN_ENTRY():
    return RevEngPlugin()
