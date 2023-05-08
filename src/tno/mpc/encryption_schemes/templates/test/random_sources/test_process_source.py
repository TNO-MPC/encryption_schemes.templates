"""
File containing all tests related to the ProcessSource.
"""
# pylint: disable=missing-function-docstring
import time

import pytest

from tno.mpc.encryption_schemes.templates._randomness_manager import PauseIteration
from tno.mpc.encryption_schemes.templates.random_sources import ProcessSource


def generation_function() -> int:
    """
    Dummy generation function.

    :return: Fixed "random" number.
    """
    return 42


def test_if_process_source_not_opened_raises_valueerror() -> None:
    source = ProcessSource(generation_function)
    with pytest.raises(ValueError):
        source.get_one()


def test_if_request_when_no_amount_given_then_raises_pauseiteration() -> None:
    with pytest.raises(PauseIteration):
        with ProcessSource(generation_function) as source:
            source.get_one()


def test_if_request_when_amount_exceeded_then_raises_pauseiteration() -> None:
    with pytest.raises(PauseIteration):
        with ProcessSource(generation_function, amount=1) as source:
            for _ in range(2):
                source.get_one()


def test_if_request_one_then_yields_one() -> None:
    with ProcessSource(generation_function, amount=1) as source:
        values = [source.get_one() for _ in range(1)]
    assert len(values) == 1


def test_if_request_two_then_yields_two() -> None:
    with ProcessSource(generation_function, amount=2) as source:
        values = [source.get_one() for _ in range(2)]
    assert len(values) == 2


def test_if_amount_two_then_nr_requested_two() -> None:
    source = ProcessSource(generation_function, amount=2)
    assert source.nr_requested == 2


def test_if_request_two_then_nr_yielded_equals_two() -> None:
    with ProcessSource(generation_function, amount=2) as source:
        for _ in range(2):
            source.get_one()
    assert source.nr_yielded == 2


def test_if_increase_requested_then_nr_requested_increases() -> None:
    with ProcessSource(generation_function, amount=2) as source:
        source.increase_requested(2)
    assert source.nr_requested == 4


def test_if_increase_requested_then_yields_more() -> None:
    with ProcessSource(generation_function, amount=0) as source:
        source.increase_requested(1)
        values = [source.get_one() for _ in range(1)]
    assert len(values) == 1


def test_if_increase_requested_before_booting_then_yields_more() -> None:
    source = ProcessSource(generation_function, amount=2)
    source.increase_requested(1)
    with source:
        values = [source.get_one() for _ in range(3)]
    assert len(values) == 3


def test_if_pool_closed_then_generated_values_still_available() -> None:
    with ProcessSource(generation_function, amount=1) as source:
        time.sleep(0.1)
    values = [source.get_one() for _ in range(1)]
    assert len(values) == 1
