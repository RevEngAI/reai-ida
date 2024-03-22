from ida_hexrays import init_hexrays_plugin
from ida_idaapi import PLUGIN_SKIP, PLUGIN_OK
from ida_kernwin import get_kernel_version
from idaapi import plugin_t, PLUGIN_FIX, PLUGIN_KEEP

from revengai.conf import RevEngConfiguration
from revengai.manager import RevEngState
from revengai.misc.configuration import Configuration
from revengai.gui.mainform import MainForm
from revengai.gui.menubar import ConfigBar
from revengai.gui.about_view import AboutView
from revengai.gui.configuration_view import ConfigurationView
from revengai.gui.upload_view import UploadView
from revengai.gui.context_hook import ContextHook
# from revengai.handler import RenameFunctionHandler
from revengai.handler import ConfigurationHandler
from revengai.logger import plugin_logger
from revengai.api import Endpoint

#
# 1. Be able to log in with API key - Done
# 2. Be able to get list of AI models from endpoints - Done
# 3. a. right click select and upload binary
#    b. go from tool bar at the top
# 4. right click on function decompiler RevEng.ai -> rename to similar function that brings up another windows
#    shows:
#       refresh button
#       rename function button
#       <function name> <confidence> <from - like library name or other binary>
# 5. batch analysis of functions -> select confidence level and it will automatically rename functions that meet this confidence level.
# 6. right click, explain function.
#

API_KEY = "bdee5ee1-17c9-4949-ae94-5a431597-e085"


class Plugin(plugin_t):
    flags = PLUGIN_FIX
    comment = "AI-assisted reverse engineering from RevEng.ai"
    help = "Configure IDA plugin for RevEng.ai"
    wanted_name = "RevEng.AI"

    def init(self):
        # stop plugin from being unloaded once we have run.
        plugin_logger.debug("plugin init")

        # idaapi.set_dock_pos(self.wanted_name, "IDA View-A", idaapi.DP_TAB)

        # configuration of plugin
        self.configuration: Configuration = Configuration()

        # threaded requests
        self.endpoint: Endpoint = Endpoint(self.configuration)

        # setup the UI hooks for the menu buttons
        self.handlers = {
            "menu_open_configuration": ConfigurationHandler,
            # "rename_function": RenameFunctionHandler,
        }

        # setup the views within the main configuration form
        self.views = {
            "About": AboutView(),
            "Configuration": ConfigurationView(self.configuration, self.endpoint),
            "Upload": UploadView(self.configuration, self.endpoint),
        }

        # create the main configuration form
        self.form = MainForm(self.views, self.configuration)

        # add the menu-bar buttons
        self.configbar = ConfigBar(
            self.form,
            self.endpoint,
            self.handlers["menu_open_configuration"],
        )

        # setup the Context (aka right-click menu) UI hooks
        self.hooks = ContextHook(
            self.form,
            self.endpoint,
            self.configuration,
            self.views["Upload"],
        )

        self.hooks.hook()
        return PLUGIN_KEEP

    def run(self, arg):
        # called when clicked via edit -> plugin
        plugin_logger.debug("plugin run")
        pass

    def term(self):
        # called when plugin is unloaded
        plugin_logger.debug("plugin term")
        self.configuration.persistConfig()
        pass


class RevEngPlugin(plugin_t):
    # variables required by IDA
    flags = 0  # normal plugin
    wanted_name = "RevEng.AI"
    help = "Configure IDA plugin for RevEng.ai"
    comment = "AI-assisted reverse engineering from RevEng.ai"
    wanted_hotkey = "Ctrl-Shift-R"
    initialized = False

    def __init__(self):
        super(RevEngPlugin, self).__init__()
        self.initialized = False

        self.state = RevEngState(RevEngConfiguration())

    def init(self):
        if not init_hexrays_plugin():
            return PLUGIN_SKIP

        kv = get_kernel_version().split(".")
        if int(kv[0]) < 8:
            return PLUGIN_SKIP
        return PLUGIN_OK

    def reload_plugin(self):
        if self.initialized:
            self.term()

        RevEngConfiguration()
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
    # return Plugin()
