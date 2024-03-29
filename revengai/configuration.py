import ida_nalt
import idaapi
from binascii import hexlify
from pathlib import Path
from json import loads, dumps
from typing import Dict, Union
from revengai.logger import plugin_logger, temp_dir


class Configuration:
    # TODO - use idaapi.get_user_idadir() instead as the location instead???
    _filename = "reveng.conf"
    _dir = temp_dir
    _path = Path(_dir, _filename)

    def __init__(self) -> None:
        self._config = {}
        self._valid = False
        self.readConfig()

        # contains information about the currently opened binary,
        # whether it has been uploaded or not and other information about.
        # TODO - We need to figure out whether we can fill this information when
        # when the file is opened
        self._context = {}

    def persistConfig(self) -> None:
        if len(self._config.keys()) > 0:
            try:
                with open(Configuration._path, "w", encoding="utf-8") as config_file:
                    config_file.write(dumps(self._config))
            except Exception as e:
                plugin_logger.error(f"[EXCEPTION] -> {e}")
        else:
            plugin_logger.debug("not writing configuration as config is empty")

    def readConfig(self) -> None:
        plugin_logger.info(f"Attemping to read config file {Configuration._path}")
        if Path.exists(Configuration._path):
            try:
                with open(Configuration._path, "r", encoding="utf-8") as config_file:
                    self._config = loads(config_file.read())
                    plugin_logger.info("Plugin configuration loaded OK!")
            except Exception as e:
                plugin_logger.warn(f"[EXCEPTION] -> {e}")
        else:
            plugin_logger.info("No configuration file found")

        self._valid = True

    def update(self, host: str, port: str, key: str) -> None:
        # NOTE - model is updated when user selects the value from the drop down list
        plugin_logger.debug(f"Updated configuration")
        self._config["host"] = host
        self._config["port"] = port
        self._config["key"] = key
        self._valid = True

    def add_file_tracking(self, hash: str, data) -> None:
        plugin_logger.info(f"adding file {hash} for tracking")
        if "tracked_files" not in self._config.keys():
            self._config["tracked_files"] = {}
        self._config["tracked_files"][hash] = data

    def remove_file_tracking(self, hash: str) -> None:
        plugin_logger.info(f"removing file {hash} from tracking")
        if "tracked_files" in self._config.keys():
            del self._config["tracked_files"][hash]

    def get_current_files(self) -> Union[Dict, None]:
        if "tracked_files" in self._config.keys():
            return self._config["tracked_files"]
        else:
            None

    def get_tracked_files_number(self) -> int:
        if "tracked_files" in self._config.keys():
            return len(self._config["tracked_files"].keys())
        else:
            return 0

    @property
    def config(self) -> any:
        return self._config

    @property
    def context(self) -> any:
        # represents useful information related to the currently opened file
        return self._context

    def initialise_cache(self) -> any:
        """
        Initialises the cache to default value, this needs to happen when the file is initially opened.

        ## TODO ## - Figure out when to best call this method?

        """
        self._context["file_name"] = idaapi.get_input_file_path()
        self._context["sha256"] = hexlify(ida_nalt.retrieve_input_file_sha256()).decode()
        self._context["file_bytes"] = idaapi.get_file
        self._context["is_uploaded"] = False
        self._context["selected_analysis"] = -1  # -1 means no analysis has been selected

    def is_valid(self) -> bool:
        expected = ["host", "port", "key"]
        return True if all(k in self._config.keys() for k in expected) else False
