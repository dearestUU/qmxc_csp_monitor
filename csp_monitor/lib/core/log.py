import sys
import logging
import colorlog
import os
from datetime import datetime
from csp_monitor.lib.core.enums import CUSTOM_LOGGING
from csp_monitor.lib.core.setting import LOG_PATH

logging.addLevelName(CUSTOM_LOGGING.SYSINFO, "*")
logging.addLevelName(CUSTOM_LOGGING.SUCCESS, "+")
logging.addLevelName(CUSTOM_LOGGING.ERROR, "-")
logging.addLevelName(CUSTOM_LOGGING.WARNING, "!")


LOGGER = logging.getLogger("csp_monitor")


LOGGER_HANDLER = logging.StreamHandler(sys.stdout)


PRIMARY_FMT = "%(cyan)s[%(asctime)s] %(log_color)s[%(levelname)s]%(reset)s %(message)s"
CUSTOM_FMT = "%(log_color)s[%(asctime)s] [%(levelname)s] %(message)s"

FORMATTER = colorlog.LevelFormatter(
    fmt={
        "DEBUG": PRIMARY_FMT,
        "INFO": PRIMARY_FMT,
        "WARNING": PRIMARY_FMT,
        "ERROR": PRIMARY_FMT,
        "CRITICAL": PRIMARY_FMT,
        "*": CUSTOM_FMT,
        "+": CUSTOM_FMT,
        "-": CUSTOM_FMT,
        "!": CUSTOM_FMT
    },
    datefmt="%H:%M:%S",
    log_colors={
        '*': 'cyan',
        '+': 'green',
        '-': 'red',
        '!': 'yellow',
        'DEBUG': 'blue',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bg_red,white'
    },
    secondary_log_colors={},
    style='%'
)
LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.setLevel(logging.INFO)
LOGGER.addHandler(LOGGER_HANDLER)


def LOGGER_R():
    if not os.path.exists(path=LOG_PATH):
        os.mkdir(LOG_PATH)
    filename = 'logs' + datetime.now().strftime('%Y%m%d') + '.log'
    filepath = os.path.join(LOG_PATH, filename)
    if filename not in os.listdir(LOG_PATH):
        with open(filepath, 'a') as f:
            f.write('\n')
    file_fmt = '[%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s] %(message)s'
    logging.basicConfig(level=logging.INFO, filename=filepath, format=file_fmt, filemode='a+')
    return logging
