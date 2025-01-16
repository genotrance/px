import os

import pytest

from px.config import *


@pytest.mark.parametrize("location, expected", [
    (LOG_NONE, None),
    (LOG_SCRIPTDIR, get_script_dir()),
    (LOG_CWD, os.getcwd()),
    (LOG_UNIQLOG, os.getcwd()),
    (LOG_STDOUT, sys.stdout),
])
def test_get_logfile(location, expected):
    result = get_logfile(location)
    if isinstance(result, str):
        result = os.path.dirname(result)
    assert expected == result
