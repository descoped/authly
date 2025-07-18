import logging
import sys


class LoggerWriter:
    def __init__(self, level_fn):
        self._level_fn = level_fn
        self._buf = ""

    def write(self, buf):
        # Remove empty lines
        for line in buf.rstrip().splitlines():
            if line.strip():
                self._level_fn(line.rstrip())

    def flush(self):
        pass

    @staticmethod
    def isatty():
        # Add this to handle uvicorn's terminal check
        return False


def setup_logging(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"):
    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add handler with desired format
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(format))
    root_logger.addHandler(handler)

    # Redirect stdout/stderr to catch container and uvicorn output
    sys.stdout = LoggerWriter(root_logger.info)
    sys.stderr = LoggerWriter(root_logger.error)
