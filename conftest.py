# Pytest configuration: sets isolated test database and adds root directory to sys.path
import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

TEST_DB_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'test_vault.db')
os.environ['DATABASE_PATH'] = TEST_DB_PATH

@pytest.fixture(scope='session', autouse=True)
def setup_test_suite_db():
    import database as db
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except OSError:
            pass
    db.init_db(TEST_DB_PATH)
    yield
    if os.path.exists(TEST_DB_PATH):
        try:
            os.remove(TEST_DB_PATH)
        except OSError:
            pass
