# -*- coding: utf-8 -*-
from os import makedirs
from pathlib import Path
from shutil import rmtree
from logging.config import fileConfig


LOG_CONFIG_FILENAME = "log.ini"
LOG_FILENAME = "reai.log"


def clear_logs(log_dir: str) -> None:
    rmtree(log_dir, ignore_errors=True)


def configure_loggers(log_dir: str) -> None:
    makedirs(log_dir, exist_ok=True)

    log_main_file: Path = Path(log_dir) / LOG_FILENAME
    log_conf_file: Path = Path(__file__).resolve().parent / LOG_CONFIG_FILENAME

    fileConfig(
        fname=log_conf_file.as_posix(),
        defaults={"default_log_filename": log_main_file.as_posix()},
    )
