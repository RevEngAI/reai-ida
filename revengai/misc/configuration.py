# -*- coding: utf-8 -*-

from os import makedirs
from json import loads, dumps
from os.path import join, exists


from ida_diskio import get_user_idadir

from reait.api import re_conf
from revengai.logger import plugin_logger


class Configuration(object):
    _filename = ".reai.cfg"
    _dir = join(get_user_idadir(), "plugins")

    def __init__(self) -> None:
        makedirs(Configuration._dir, mode=0o755, exist_ok=True)

        self._config = {}

        self.readConfig()

    def get(self, name: str) -> any:
        return self._config.get(name)

    def set(self, name: str, value: any = None) -> None:
        if value is None:
            self._config.pop(name, value)
        else:
            self._config[name] = value

    def persistConfig(self) -> None:
        try:
            if self.is_valid():
                re_conf["apikey"] = self._config["apikey"]

            with open(join(Configuration._dir, Configuration._filename), "w") as fd:
                fd.write(dumps(self._config))
        except Exception as e:
            plugin_logger.error(f"[EXCEPTION] -> {e}")

    def readConfig(self) -> None:
        if exists(join(Configuration._dir, Configuration._filename)):
            try:
                with open(join(Configuration._dir, Configuration._filename), "r") as fd:
                    self._config = loads(fd.read())

                if self.is_valid():
                    re_conf["apikey"] = self._config["apikey"]
            except Exception as e:
                plugin_logger.error(f"[EXCEPTION] -> {e}")
        else:
            self._config["host"] = re_conf["host"]

    @property
    def config(self) -> any:
        return self._config

    def is_valid(self) -> bool:
        return all(self.get(name) is not None for name in ["apikey", "host", "model"])
