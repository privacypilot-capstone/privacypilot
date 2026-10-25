"""
Test, mock and fixture code.

Data in a repository's tests (a sample Aadhaar number in a unit test, a mock
user with a phone number) is not personal data the application collects,
shares or logs. Findings in such files are still stored and shown, but by
default they do not produce DPDP violations, do not create consent gaps and
do not count as a module's use of a data category.

Set PRIVACYPILOT_INCLUDE_TEST_CODE=1 to treat test code like any other code.
Schema migrations are treated the same way: they record past table layouts,
which the models already describe.
"""
import os
import re
from pathlib import PurePosixPath

_TEST_DIRS = {
    "test", "tests", "__tests__", "_tests_", "spec", "specs", "__mocks__", "mocks",
    "mock", "fixtures", "__fixtures__", "testdata", "test-data", "test_data", "e2e",
    "cypress", "migrations",
}
# file names: test_x.py, x_test.py, x.test.ts, x.spec.ts, x-spec.data.ts,
# x.mock.ts, x.mock.data.ts, conftest.py, x.stories.tsx
_TEST_FILE_RE = re.compile(
    r"(?:^test_.*\.py$|_test\.py$|^conftest\.py$"
    r"|(?:^|[._-])(?:spec|test|tests|mock|mocks|stories)(?:[._-][^/]*)?\.(?:[cm]?js|jsx|ts|tsx|py)$)",
    re.I,
)


def include_test_code() -> bool:
    return os.getenv("PRIVACYPILOT_INCLUDE_TEST_CODE", "0").lower() in ("1", "true", "yes")


def is_test_path(path: str | None) -> bool:
    """True for a file in a test/mock/fixture/migration directory or with a
    test file name."""
    if not path:
        return False
    p = PurePosixPath(path.replace("\\", "/"))
    if any(part.lower() in _TEST_DIRS for part in p.parts[:-1]):
        return True
    return bool(_TEST_FILE_RE.search(p.name))


def counts_for_rules(path: str | None) -> bool:
    """Whether a finding in this file can produce violations."""
    return include_test_code() or not is_test_path(path)
