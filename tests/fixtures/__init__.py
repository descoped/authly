from fixtures.setup_logging import setup_logging
from fixtures.testing.lifespan import *  # noqa
from fixtures.testing.postgres import *  # noqa

setup_logging(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s'
)
