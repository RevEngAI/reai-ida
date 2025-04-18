import idaapi
import logging
import ida_auto
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
from revengai.misc.qtutils import inthread

from revengai.manager import RevEngState
import urllib3
from revengai.gui import Requests
import importlib
import idc

from revengai.misc.utils import IDAUtils

from reait.api import (
    RE_functions_rename,
    RE_analyze_functions,
)

from requests.exceptions import HTTPError


logger = logging.getLogger("REAI")


class FunctionRenameHook(idaapi.IDP_Hooks):
    state: RevEngState
    function_map: dict[int, int] = {}
    image_base: int = 0

    def __init__(self, state: RevEngState):
        self.state = state
        self.image_base = idaapi.get_imagebase()
        idaapi.IDP_Hooks.__init__(self)
        self.last_names = {}
        # Initialize with current function names
        for func_ea in Functions():
            self.last_names[func_ea] = IDAUtils.get_demangled_func_name(
                func_ea
            )
        logger.info(
            f"FunctionRenameHook initialized with {len(self.last_names)}"
            " functions"
        )

    def _get_function_id(self, fpath: str,  ea: int) -> int:
        """
        Get the function ID for a given address.

        Args:
            ea (int): The address of the function.

        Returns:
            int: The function ID.
        """
        # first subtract the base address of the binary from the address
        # to get the relative address
        ea = ea - self.image_base

        if self.function_map is not None and len(self.function_map) > 0:
            return self.function_map.get(ea, -1)

        try:
            binary_id = self.state.config.get("binary_id", 0)

            if binary_id == 0:
                logger.warning(
                    "Binary ID is not set. please analyze the file first."
                )
                return -1

            res: dict = RE_analyze_functions(
                fpath, binary_id
            ).json()

            functions = res.get("functions", [])

            for function in functions:
                func_id = function.get("function_id", -1)
                func_vaddr = function.get("function_vaddr", "")
                self.function_map[func_vaddr] = func_id

            return self.function_map.get(ea, -1)
        except HTTPError as e:
            resp = e.response.json()
            detail = resp.get("detail", [])
            if len(detail) > 0:
                error = detail[0].get("msg", "Unknown error")
            else:
                error = "Unknown error"
            logger.error(f"Failed to get function ID for {hex(ea)}: {error}")
            return -1

    def ev_rename(self, ea, new_name):
        fpath = idc.get_input_file_path()
        if is_condition_met(self.state, fpath):
            def bg_task() -> None:
                done, _ = is_analysis_complete(self.state, fpath)
                old_name = self.last_names.get(ea, "")
                if done:
                    # rename the function in the database
                    if old_name != new_name:
                        self.last_names[ea] = new_name
                        try:
                            function_id = self._get_function_id(fpath, ea)

                            # check if the function ID is valid
                            if function_id == -1:
                                logger.error(
                                    "Failed to get function ID for %s",
                                    hex(ea),
                                )
                                return

                            logging.info(
                                "EventHook - Renaming function "
                                f"{function_id} to {new_name}"
                            )
                            # renaming the function in the database
                            RE_functions_rename(
                                function_id,
                                new_name
                            )
                        except HTTPError as e:
                            logger.error(
                                "Failed to rename function: %s", str(e)
                            )
                            return
                    else:
                        logger.info(
                            "Function name is the same, skipping rename"
                        )
                else:
                    logger.warning(
                        "Analysis is not complete, skipping function rename"
                    )
                    # logger.info(
                    #     f"Renaming function {new_name} back to {old_name}"
                    # )
                    # inmain(IDAUtils.set_name, ea, old_name)
                    self.last_names[ea] = new_name
                    return
            inthread(bg_task)
        else:
            logger.warning(
                "Cannot rename function our the platform as long as the"
                " plugin is not configured"
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
        self.auto_analysis_complete = False
        self.state = RevEngState()

        global plugin_instance
        plugin_instance = self

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

        # If auto-analysis is already finished, initialize immediately
        if ida_auto.auto_is_ok():
            logger.info("Auto-analysis is complete, initializing hooks")
            self.initialize_hook()
            self.auto_analysis_complete = True
        else:
            logger.info(
                "Auto-analysis is not complete, waiting for it to finish"
            )
            # Otherwise, set up a UI hook to wait for auto-analysis to finish
            idaapi.register_timer(500, check_analysis_status)

        self.run()
        return PLUGIN_KEEP

    def initialize_hook(self):
        """
        Initialize the function rename hook after auto-analysis is complete
        """
        logger.info("Initializing function rename hook")
        self.hook = FunctionRenameHook(self.state)
        self.hook.hook()

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

        if hasattr(self, 'hook') and self.hook is not None:
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


# Global variable to store the plugin instance
plugin_instance: RevEngPlugin = None


def check_analysis_status():
    """Timer callback to check if auto-analysis is complete"""
    global plugin_instance

    if ida_auto.auto_is_ok():
        logger.info("Auto-analysis is complete")
        if plugin_instance and not plugin_instance.auto_analysis_complete:
            plugin_instance.initialize_hook()
            plugin_instance.auto_analysis_complete = True
        else:
            logger.info("plugin istance is None or already initialized")
        return -1  # Stop the timer
    logger.info(
        "Auto-analysis is not complete, waiting for it to finish..."
    )
    return 500  # Continue checking every 500ms


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
