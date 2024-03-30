# -*- coding: utf-8 -*-
import logging

from ida_kernwin import get_kernel_version
from idaapi import plugin_t, PLUGIN_FIX, PLUGIN_SKIP, PLUGIN_OK, PLUGIN_KEEP

from revengai.conf import RevEngConfiguration
from revengai.manager import RevEngState

logger = logging.getLogger("REAI")


class RevEngPlugin(plugin_t):
    # variables required by IDA
    flags = PLUGIN_FIX  # normal plugin
    wanted_name = "RevEng.AI"
    help = "Configure IDA plugin for RevEng.AI"
    comment = "AI-assisted reverse engineering from RevEng.AI"
    initialized = False

    def __init__(self):
        super(RevEngPlugin, self).__init__()

        self.state = RevEngState(RevEngConfiguration())

    def init(self):
        kv = get_kernel_version().split(".")
        if int(kv[0]) < 8:
            logger.info("REAI need IDA version >= 8.0. Skipping")
            return PLUGIN_SKIP

        logger.info("REAI initialized")

        if self.state.config.auto_start:
            self.run()
            return PLUGIN_KEEP
        return PLUGIN_OK

    def reload_plugin(self):
        if self.initialized:
            self.term()

        logger.info("REAI reloading...")

        self.state.start_plugin()
        self.initialized = True

    def run(self, args=None):
        self.reload_plugin()

    def term(self):
        logger.info("Terminating REAI...")
        if self.state is not None:
            self.state.stop_plugin()

        self.initialized = False


def PLUGIN_ENTRY():
    return RevEngPlugin()
