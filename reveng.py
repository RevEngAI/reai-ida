import ida_funcs
import idaapi
import logging

from idc import (
    get_inf_attr,
    APPT_LIBRARY,
    APPT_PROGRAM,
    INF_APPTYPE,
    INF_FILETYPE,
    FT_ELF,
    FT_PE,
    FT_MACHO,
    FT_EXE,
    FT_BIN,
)

from idaapi import (
    execute_ui_requests,
    plugin_t,
    IDA_SDK_VERSION,
    PLUGIN_SKIP,
    PLUGIN_KEEP,
    PLUGIN_HIDE,
    PLUGIN_UNL,
)

from idautils import (
    Functions,
)

from revengai.actions import is_condition_met, is_analysis_complete
from revengai.gui.dialog import Dialog
from revengai.misc.qtutils import inthread, inmain

from revengai.manager import RevEngState
import urllib3
from revengai.gui import Requests
import importlib
import idc

from revengai.misc.utils import IDAUtils


logger = logging.getLogger("REAI")


class FunctionRenameHook(idaapi.IDP_Hooks):
    state: RevEngState

    def __init__(self, state: RevEngState):
        self.state = state
        idaapi.IDP_Hooks.__init__(self)
        self.last_names = {}
        # Initialize with current function names
        for func_ea in Functions():
            if IDAUtils.is_in_valid_segment(func_ea):
                self.last_names[func_ea] = IDAUtils.get_demangled_func_name(
                    func_ea
                )

        logger.info(f"FunctionRenameHook initialized: {self.last_names}")

    def ev_rename(self, ea, new_name):
        fpath = idc.get_input_file_path()

        if is_condition_met(self.state, fpath):

            def bg_task() -> None:
                done, status = is_analysis_complete(self.state, fpath)
                if done:
                    # rename the function in the database
                    old_name = self.last_names.get(ea, "")
                    if old_name != new_name:
                        self.last_names[ea] = new_name
                else:
                    logger.warning(
                        "Analysis is not complete, skipping function rename"
                    )

            inthread(bg_task)
        else:
            logger.warning(
                "Cannot rename function our the platform as long as the"
                " plugin is not configured"
            )
        # Check if the renamed item is a function
        # func = ida_funcs.get_func(ea)
        # if func:
        #     old_name = self.last_names.get(func.start_ea, "")
        #     if old_name != new_name:
        #         # Your custom action goes here
        #         print(
        #             f"Function renamed: {old_name} -> {new_name} at 0x{func.start_ea:X}")

        #         # Example of custom action: log to a file
        #         with open("function_renames.log", "a") as f:
        #             f.write(f"0x{func.start_ea:X}: {old_name} -> {new_name}\n")

        #         # Update our record of the name
        #         self.last_names[func.start_ea] = new_name

        # # Must return 0 to let IDA process the event
        # return 0
        logger.info(
            f"Function renamed: {self.last_names.get(ea, '')} -> {new_name} at 0x{ea:X}"
        )
        return 0


class RevEngPlugin(plugin_t):
    """
    Define the plugin class itself which is returned by the PLUGIN_ENTRY method
    that scriptable plugins use to be recognized within IDA
    """

    # Variables required by IDA
    # Use the HIDE to avoid the entry in Edit/Plugins since this plugin's run()
    # method has no functionality.
    flags = 0 if IDA_SDK_VERSION > 810 else PLUGIN_HIDE
    wanted_hotkey = ""
    wanted_name = "RevEngAI"
    help = f"Configure IDA plugin for {wanted_name}"
    comment = f"AI-assisted reverse engineering from {wanted_name}"
    hook: FunctionRenameHook = None

    def __init__(self):
        super(RevEngPlugin, self).__init__()

    def init(self) -> int:
        """
        Called when the plugin is initialised.
        """
        self.initialized = False
        self.state = RevEngState()
        self.hook = FunctionRenameHook(self.state)

        if IDA_SDK_VERSION < 800:
            logger.warning("%s support 8.X IDA => skipping...",
                           self.wanted_name)
            return PLUGIN_SKIP
        elif get_inf_attr(INF_APPTYPE) not in (
            APPT_LIBRARY,
            APPT_PROGRAM,
        ) and get_inf_attr(INF_FILETYPE) not in (
            FT_BIN,
            FT_PE,
            FT_ELF,
            FT_EXE,
            FT_MACHO,
        ):
            logger.warning(
                "%s supports PE, ELF, RAW, EXE, DLL and Mach-O file types =>"
                " skipping...",
                self.wanted_name,
            )
            return PLUGIN_UNL

        logger.info("%s plugin starts", self.wanted_name)

        self.hook.hook()
        self.run()
        return PLUGIN_KEEP

    def run(self, _=None) -> bool:
        if self.initialized:
            self.term()

        logger.info("Starting %s..", self.wanted_name)

        # NOTE: the first call initialises the GUI components
        self.state.start_plugin()
        # NOTE: the second call actually invokes the creation of the GUI
        self.state.start_plugin()

        self.initialized = True
        return True

    def term(self) -> None:
        """
        Called when the plugin is unloaded.
        """
        logger.info("Terminating %s...", self.wanted_name)
        if self.state is not None:
            self.state.stop_plugin()

        if hasattr(self, 'hook'):
            self.hook.unhook()
        self.initialized = False


def is_dependency_installed(package_name):
    """
    Check if a Python package is installed.
    Works for Python 3.10 - 3.12

    Args:
        package_name (str): Name of the package to check

    Returns:
        bool: True if package is installed, False otherwise
    """
    try:
        spec = importlib.util.find_spec(package_name)
        return spec is not None
    except (ImportError, AttributeError):
        return False


def check_dependencies(required_packages):
    """
    Check if all required packages are installed.

    Args:
        required_packages (list): List of package names to check

    Returns:
        tuple: (bool, list) - (all packages installed, missing packages)
    """
    missing_packages = []

    for package in required_packages:
        if not is_dependency_installed(package):
            missing_packages.append(package)

    return len(missing_packages) == 0, missing_packages


# The PLUGIN_ENTRY method is what IDA calls when scriptable plugins are loaded.
# It needs to return a plugin of type idaapi.plugin_t.
def PLUGIN_ENTRY():
    requested_libraries = ["reait", "libbs"]

    all_installed, missing_libraries = check_dependencies(requested_libraries)

    if all_installed:
        # Workaround to suppress warnings about SSL certificates
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        return RevEngPlugin()
    else:
        idc.msg(
            "[!] RevEng.AI Toolkit requires the dependencies to be "
            "installed.\n"
            "    Missing libraries: %s\n"
            "    Please install them using the following command:\n"
            "    pip install %s\n"
            % (
                ", ".join(missing_libraries),
                " ".join(requested_libraries),
            )
        )

    execute_ui_requests(
        (
            Requests.MsgBox(
                RevEngPlugin.wanted_name,
                "Unable to load all the required modules.",
                -1
            ),
        )
    )
    return None
