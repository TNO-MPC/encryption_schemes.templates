"""
File containing all tests related to the FileSource.
"""
# pylint: disable=missing-function-docstring
from __future__ import annotations

import sys
import time
from pathlib import Path
from queue import Queue
from typing import Any

import pytest

from tno.mpc.encryption_schemes.templates.random_sources import FileSource

# Set timeout method for pytest-timeout. The "signal" mode (default value when available) is more
# graceful, yet unable to stop hanging threads for python<3.9.
if sys.version_info < (3, 9):
    TIMEOUT_METHOD = "thread"
else:
    TIMEOUT_METHOD = None

FILEPATH_COMMA_SEPARATED = Path(__file__).parent / "numbers_sep_comma.txt"
FILEPATH_NEWLINE_SEPARATED = Path(__file__).parent / "numbers_sep_newline.txt"


# Perform this test early -- if it fails, other tests _may_ also fail with non-informative errors
def test_when_file_and_queue_depleted_if_thread_closes_slowly_then_raises_stopiteration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """
    When the file and queue are depleted, get_one should raise a StopIteration. However, it can
    happen that the file thread is closing but still running. A StopIteration should be raised even
    if the thread closes slightly after the call to get_one.

    :param monkeypatch: Monkeypatch fixture.
    """

    def slowly_closing_file_thread(*_args: Any, **_kwargs: Any) -> None:
        time.sleep(1.5)

    source = FileSource(
        FILEPATH_COMMA_SEPARATED, delimiter=",", retry_attempts=3, retry_wait_s=1
    )
    monkeypatch.setattr(source, "_file_thread_fn", slowly_closing_file_thread)

    with pytest.raises(StopIteration):
        with source:
            source.get_one()


def test_if_file_source_not_opened_raises_valueerror() -> None:
    source = FileSource(FILEPATH_COMMA_SEPARATED)
    with pytest.raises(ValueError):
        source.get_one()


def test_if_request_one_then_yields_one() -> None:
    with FileSource(FILEPATH_COMMA_SEPARATED, delimiter=",") as source:
        values = [source.get_one() for _ in range(1)]
    assert len(values) == 1


def test_if_request_two_then_yields_two() -> None:
    with FileSource(FILEPATH_COMMA_SEPARATED, delimiter=",") as source:
        values = [source.get_one() for _ in range(2)]
    assert len(values) == 2


def test_if_request_two_then_nr_yielded_equals_two() -> None:
    with FileSource(FILEPATH_COMMA_SEPARATED, delimiter=",") as source:
        for _ in range(2):
            source.get_one()
    assert source.nr_yielded == 2


def test_if_request_from_comma_separated_then_yields_contents() -> None:
    with FileSource(FILEPATH_COMMA_SEPARATED, delimiter=",") as source:
        values = [source.get_one() for _ in range(5)]
    assert values == [1, 2, 3, 4, 5]


def test_if_request_from_newline_separated_then_yields_contents() -> None:
    with FileSource(FILEPATH_NEWLINE_SEPARATED, delimiter="\n") as source:
        values = [source.get_one() for _ in range(5)]
    assert values == [1, 2, 3, 4, 5]


def test_if_filethread_closed_then_read_numbers_still_available() -> None:
    with FileSource(FILEPATH_COMMA_SEPARATED, delimiter=",") as source:
        time.sleep(0.1)
    values = [source.get_one() for _ in range(1)]
    assert len(values) == 1


def test_if_request_too_many_then_raises_stopiteration() -> None:
    with pytest.raises(StopIteration):
        with FileSource(FILEPATH_COMMA_SEPARATED, delimiter=",") as source:
            for _ in range(6):
                source.get_one()


def test_when_file_thread_hangs_if_retry_sufficiently_long_then_get_one_successful(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow_file_thread(path: Path, file_queue: Queue[int | Exception]) -> None:
        del path
        time.sleep(1.5)
        file_queue.put(1)

    source = FileSource(
        FILEPATH_COMMA_SEPARATED, delimiter=",", retry_attempts=3, retry_wait_s=1
    )
    monkeypatch.setattr(source, "_file_thread_fn", slow_file_thread)

    with source:
        source.get_one()
    assert True


def test_when_file_thread_hangs_if_retry_too_short_then_get_one_then_raises_timeouterror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def slow_file_thread(*_args: Any, **_kwargs: Any) -> None:
        time.sleep(2.5)

    source = FileSource(
        FILEPATH_COMMA_SEPARATED, delimiter=",", retry_attempts=2, retry_wait_s=1
    )
    monkeypatch.setattr(source, "_file_thread_fn", slow_file_thread)

    with pytest.raises(TimeoutError):
        with source:
            source.get_one()


@pytest.mark.timeout(2, method=TIMEOUT_METHOD)
def test_when_full_queue_if_shutdown_then_shuts_down_thread() -> None:
    source = FileSource(FILEPATH_COMMA_SEPARATED, queue_size=1)

    with source:
        # allow queue to fill
        time.sleep(1)
