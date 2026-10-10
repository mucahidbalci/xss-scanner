import logging
import sys


def setup_logger():
    logger = logging.getLogger("SecAudit")
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s - %(message)s', datefmt='%H:%M:%S'))
    if not logger.handlers:
        logger.addHandler(handler)
    return logger


log = setup_logger()