import logging

from .committed_data import *  # noqa
from .setup_logging import setup_logging
from .testing.lifespan import *  # noqa
from .testing.postgres import *  # noqa

setup_logging(level=logging.INFO, log_format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
