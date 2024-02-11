from idaapi import plugin_t, PLUGIN_FIX, PLUGIN_KEEP
from revengai.configuration import Configuration
from revengai.gui.mainform import MainForm
from revengai.gui.menubar import ConfigBar
from revengai.gui.about_view import AboutView
from revengai.gui.configuration_view import ConfigurationView
from revengai.gui.upload_view import UploadView
from revengai.gui.context_hook import ContextHook
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

        # configuration of plugin
        self.configuration: Configuration = Configuration()

        # threaded requests
        self.endpoint: Endpoint = Endpoint(self.configuration)

        # setup the UI hooks for the menu buttons
        self.handlers = {
            "menu_open_configuration": ConfigurationHandler,
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


def PLUGIN_ENTRY():
    plugin_logger.debug("global plugin entry called")
    return Plugin()
