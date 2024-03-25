# -*- coding: utf-8 -*-

from ida_idaapi import PLUGIN_SKIP, PLUGIN_OK
from ida_kernwin import get_kernel_version
from idaapi import plugin_t, PLUGIN_FIX

from revengai.conf import RevEngConfiguration
from revengai.manager import RevEngState


class RevEngPlugin(plugin_t):
    # variables required by IDA
    flags = PLUGIN_FIX  # normal plugin
    wanted_name = "RevEng.AI"
    help = "Configure IDA plugin for RevEng.ai"
    comment = "AI-assisted reverse engineering from RevEng.ai"
    initialized = False

    def __init__(self):
        super(RevEngPlugin, self).__init__()
        self.initialized = False

        self.state = RevEngState(RevEngConfiguration())

    def init(self):
        kv = get_kernel_version().split(".")
        if int(kv[0]) < 8:
            return PLUGIN_SKIP
        return PLUGIN_OK

    def reload_plugin(self):
        if self.initialized:
            self.term()

        self.state.start_plugin()
        self.initialized = True

    def run(self, args):
        self.reload_plugin()

    def term(self):
        if self.state is not None:
            self.state.stop_plugin()

        self.initialized = False


def PLUGIN_ENTRY():
    return RevEngPlugin()
