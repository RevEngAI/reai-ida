# -*- coding: utf-8 -*-

from os import makedirs
from json import loads, dumps
from os.path import join, exists


from ida_diskio import get_user_idadir

from reait.api import re_conf
from revengai.logger import plugin_logger


class RevEngConfiguration(object):
    _filename = ".reai.cfg"
    _dir = join(get_user_idadir(), "plugins")

    auto_start = True

    def __init__(self) -> None:
        makedirs(RevEngConfiguration._dir, mode=0o755, exist_ok=True)

        self._config = {}

        self.readConfig()

    def get(self, name: str) -> any:
        return self.config.get(name)

    def set(self, name: str, value: any = None) -> None:
        if value is None:
            self.config.pop(name, value)
        else:
            self.config[name] = value

    def persistConfig(self) -> None:
        try:
            if self.is_valid():
                re_conf["apikey"] = self.config["apikey"]

            with open(join(self._dir, self._filename), "w") as fd:
                fd.write(dumps(self.config))
        except Exception as e:
            plugin_logger.error(f"[EXCEPTION] -> {e}")

    def readConfig(self) -> None:
        if exists(join(self._dir, self._filename)):
            try:
                with open(join(self._dir, self._filename), "r") as fd:
                    self._config = loads(fd.read())

                if self.is_valid():
                    re_conf["apikey"] = self.config["apikey"]
            except Exception as e:
                plugin_logger.error(f"[EXCEPTION] -> {e}")
        else:
            self.config["host"] = re_conf["host"]

    @property
    def config(self) -> dict:
        return self._config

    def is_valid(self) -> bool:
        return all(self.get(name) is not None for name in ["apikey", "host", "model"])