# -*- coding: utf-8 -*-
from os import makedirs
from json import loads, dumps
from os.path import join, exists

from requests import HTTPError
from idaapi import get_user_idadir, retrieve_input_file_sha256

from reait.api import re_conf, RE_health, RE_settings

from revengai.conf.database import RevEngDatabase
from revengai.log.log import configure_loggers
from revengai.misc.qtutils import inthread


class RevEngConfiguration(object):
    _logdir = "reai_logs"

    _filename = ".reai.cfg"
    _dir = join(get_user_idadir(), "plugins")

    auto_start = True   # Enable RevEng.AI plugin automatically

    LIMIT = 10 * 1024**2  # File size limit to upload 10MB
    PORTAL = "https://portal.reveng.ai"   # Web portal
    OPTIONS = {}    # file options currently supported by the RevEng.AI platform

    def __init__(self):
        makedirs(RevEngConfiguration._dir, mode=0o755, exist_ok=True)

        self._config = {}

        self._database = RevEngDatabase()

        configure_loggers(join(self._dir, self._logdir))

        self.restore()

    def get(self, name: str, default_val: any = None) -> any:
        return self.config.get(name, default_val)

    def set(self, name: str, value: any = None) -> None:
        if value is None:
            self.config.pop(name, value)
        else:
            self.config[name] = value

            if name in ("host", "apikey",):
                re_conf[name] = value

    def save(self) -> None:
        if self.is_valid():
            re_conf["host"] = self.config["host"]
            re_conf["apikey"] = self.config["apikey"]

        with open(join(self._dir, self._filename), "w") as fd:
            fd.write(dumps(self.config))

    def restore(self) -> None:
        if exists(join(self._dir, self._filename)):
            with open(join(self._dir, self._filename)) as fd:
                self._config = loads(fd.read())

            if self.is_valid():
                self.init_current_analysis()

                re_conf["host"] = self.config["host"]
                re_conf["apikey"] = self.config["apikey"]

                def bg_task() -> None:
                    try:
                        if RE_health():
                            response = RE_settings().json()

                            if response["success"]:
                                for option in ("isa_options", "file_options", "platform_options",):
                                    RevEngConfiguration.OPTIONS[option] = response.get(option, None)

                                RevEngConfiguration.PORTAL = response.get("portal", RevEngConfiguration.PORTAL)
                                RevEngConfiguration.LIMIT = response.get("max_file_size", RevEngConfiguration.LIMIT)
                    except HTTPError:
                        pass

                inthread(bg_task)
        else:
            self.config["host"] = re_conf["host"]

    @property
    def config(self) -> dict:
        return self._config

    def is_valid(self) -> bool:
        return all(self.get(name) is not None for name in ("apikey", "host", "model",))

    @property
    def database(self) -> RevEngDatabase:
        return self._database

    def init_current_analysis(self):
        sha_256_hash: bytes = retrieve_input_file_sha256()

        if sha_256_hash:
            self.set("binary_id", self.database.get_last_analysis(sha_256_hash.hex()))
