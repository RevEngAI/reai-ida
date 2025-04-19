from json import loads, dumps
from os import access, makedirs, R_OK
from os.path import dirname, join, isfile

from idaapi import get_input_file_path
from idaapi import get_user_idadir
from idaapi import msg
from idaapi import retrieve_input_file_sha256
from reait.api import re_conf, RE_health, RE_settings
from requests import RequestException

from revengai.api import RE_models
from revengai.conf.database import RevEngDatabase
from revengai.log.log import configure_loggers
from revengai.misc.qtutils import inthread
import logging

logger = logging.getLogger("REAI")


class RevEngConfiguration(object):
    _logdir = "reai_logs"

    _filename = ".reai.cfg"
    _dir = join(get_user_idadir(), "plugins")

    auto_start = True  # Enable RevEng.AI plugin automatically

    LIMIT = 10 * 1024 ** 2  # File size limit to upload 10MB
    PORTAL = "https://portal.reveng.ai"  # RevEng.AI Web portal
    OPTIONS = {}  # File options currently supported by RevEng.AI for analysis
    MODELS = []  # List of models that are currently being used for analysis

    def __init__(self):
        makedirs(RevEngConfiguration._dir, mode=0o755, exist_ok=True)

        self._config = {}

        self._database = RevEngDatabase()

        configure_loggers(join(self._dir, self._logdir))

        if RevEngConfiguration.auto_start:
            if get_input_file_path():
                self.restore()

    def get(self, name: str, default_val: any = None) -> any:
        return self.config.get(name, default_val)

    def set(self, name: str, value: any = None) -> None:
        if value is None:
            self.config.pop(name, value)
        else:
            self.config[name] = value

            if name in (
                    "host",
                    "apikey",
            ):
                re_conf[name] = value

    def save(self) -> None:
        if self.is_valid():
            re_conf["host"] = self.config["host"]
            re_conf["apikey"] = self.config["apikey"]

        with open(join(self._dir, self._filename), "w") as fd:
            fd.write(dumps(self.config))

    def restore(self) -> None:
        fpath = join(self._dir, self._filename)

        logger.info("Loading configuration from %s", fpath)

        if isfile(fpath) and access(fpath, R_OK):
            with open(fpath) as fd:
                self._config = loads(fd.read())

            if self.is_valid():
                re_conf["host"] = self.config["host"]
                re_conf["apikey"] = self.config["apikey"]

                def bg_task() -> None:
                    try:
                        if RE_health():
                            response = RE_models().json()

                            if response["success"]:
                                RevEngConfiguration.MODELS = [
                                    model["model_name"] for model in
                                    response["models"]
                                ]

                            response = RE_settings().json()

                            if response["success"]:
                                for option in (
                                        "isa_options",
                                        "file_options",
                                        "platform_options",
                                ):
                                    opt = response.get(option, None)
                                    RevEngConfiguration.OPTIONS[option] = opt

                                RevEngConfiguration.PORTAL = response.get(
                                    "portal", RevEngConfiguration.PORTAL
                                )
                                RevEngConfiguration.LIMIT = response.get(
                                    "max_file_size", RevEngConfiguration.LIMIT
                                )
                    except RequestException:
                        pass

                inthread(bg_task)
        else:
            inthread(RE_health)
            self.config["host"] = re_conf["host"]
            RevEngConfiguration.MODELS = []

    @property
    def config(self) -> dict:
        return self._config

    def is_valid(self) -> bool:
        return all(
            self.get(name) is not None
            for name in (
                "apikey",
                "host",
            )
        )

    @property
    def database(self) -> RevEngDatabase:
        return self._database

    def init_current_analysis(self):
        sha_256_hash: bytes = retrieve_input_file_sha256()

        if sha_256_hash:
            self.set("binary_id", self.database.get_last_analysis(
                sha_256_hash.hex()))

            msg(
                f"[+] Selecting current analysis ID {self.get('binary_id')}"
                f" for binary hash: {sha_256_hash.hex()}\n"
            )


class ProjectConfiguration(object):
    def __init__(self):
        self._path = join(dirname(__file__), "default_conf.json")
        self._project_conf = {}

        self.load()

    @property
    def project_config(self) -> dict:
        return self._project_conf

    def get(self, name: str, default_val: any = None) -> any:
        return self.project_config.get(name, default_val)

    def load(self):
        try:
            with open(self._path) as fd:
                self._project_conf = loads(fd.read())
        except FileNotFoundError:
            pass
