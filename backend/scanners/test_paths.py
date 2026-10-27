"""
Test, mock and fixture code.

Data in a repository's tests (a sample Aadhaar number in a unit test, a mock
user with a phone number) is not personal data the application collects,
shares or logs. Findings in such files are still stored and shown, but by
default they do not produce DPDP violations, do not create consent gaps and
do not count as a module's use of a data category.

Set PRIVACYPILOT_INCLUDE_TEST_CODE=1 to treat test code like any other code.

Example and demo programs (examples/, samples/, demo/ …) are treated the
same way: they show how to call a library with sample values and are not
the application processing its users' data. Set
PRIVACYPILOT_INCLUDE_EXAMPLE_CODE=1 to count them.
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


_EXAMPLE_DIRS = {
    "example", "examples", "sample", "samples", "demo", "demos",
    "example-app", "example_app", "sample-app", "sample_app", "playground",
}


def include_example_code() -> bool:
    return os.getenv("PRIVACYPILOT_INCLUDE_EXAMPLE_CODE", "0").lower() in ("1", "true", "yes")


def is_example_path(path: str | None) -> bool:
    """True for a file inside an example / sample / demo directory."""
    if not path:
        return False
    p = PurePosixPath(path.replace("\\", "/"))
    return any(part.lower() in _EXAMPLE_DIRS for part in p.parts[:-1])


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
    if is_test_path(path) and not include_test_code():
        return False
    if is_example_path(path) and not include_example_code():
        return False
    return True
