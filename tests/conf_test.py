import pytest
import server.utils as utils
from datetime import datetime


@pytest.fixture(scope='class', autouse=True)
def suite_data():
    print('Start test suite')
    yield
    print('Finish test suite')


@pytest.fixture(scope='function', autouse=True)
def case_data():
    print('Start test in {}'.format(utils.convert_date(datetime.now())))
    yield
    print('Stop test in {}'.format(utils.convert_date(datetime.now())))

