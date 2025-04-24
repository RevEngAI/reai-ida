from logging.config import fileConfig
from os import makedirs
from pathlib import Path
from shutil import rmtree
import datetime

LOG_CONFIG_FILENAME = "log.ini"
LOG_FILENAME = "reai_{date}.log"


def clear_logs(log_dir: str) -> None:
    rmtree(log_dir, ignore_errors=True)


def configure_loggers(log_dir: str) -> None:
    makedirs(log_dir, exist_ok=True)

    log_main_file: Path = Path(log_dir) / LOG_FILENAME
    lfname = LOG_CONFIG_FILENAME.format(
        date=datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    )
    log_conf_file: Path = Path(__file__).resolve().parent / lfname

    fileConfig(
        fname=log_conf_file.as_posix(),
        defaults={"default_log_filename": log_main_file.as_posix()},
    )
