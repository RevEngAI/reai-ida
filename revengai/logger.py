import logging
from pathlib import Path
from tempfile import gettempdir
from idaapi import msg

# By default logs to the default temp dir on windows which is C:\Users\<user>\AppData\Local\Temp\revengai
# configurations are persisted across sessions via the reveng.conf file saved in the same location


class IdaLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        msg(self.format(record) + "\n")


# Setup logging for the plugin
idalogger = IdaLogHandler()
plugin_logger = logging.getLogger("plugin_logger")
formatter = logging.Formatter("%(asctime)s ::%(funcName)s [%(levelname)s] - %(message)s")
# setup logging and temp dirs for writing files
plugin_logger.setLevel(logging.DEBUG)
idalogger.setFormatter(formatter)
plugin_logger.addHandler(idalogger)
if not Path.exists(Path(gettempdir(), "revengai")):
    Path.mkdir(Path(gettempdir(), "revengai"))
plugin_dir_log = Path(gettempdir(), "revengai", "reveng.log")
temp_dir = Path(gettempdir(), "revengai")
plugin_logger.addHandler(logging.FileHandler(plugin_dir_log, encoding="utf-8"))
plugin_logger.info(f"debug log {plugin_dir_log}")
plugin_logger.info(f"temp dir {temp_dir}")
