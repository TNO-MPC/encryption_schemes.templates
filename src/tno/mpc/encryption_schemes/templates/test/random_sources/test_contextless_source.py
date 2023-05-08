"""
File containing all tests related to the ContextlessSource.
"""
# pylint: disable=missing-function-docstring
import pytest

from tno.mpc.encryption_schemes.templates.random_sources import ContextlessSource


def test_if_request_one_then_yields_one() -> None:
    source = ContextlessSource([2])
    values = [source.get_one() for _ in range(1)]
    assert len(values) == 1


def test_if_request_two_then_yields_two() -> None:
    source = ContextlessSource([1, 2])
    values = [source.get_one() for _ in range(2)]
    assert len(values) == 2


def test_if_request_two_then_nr_yielded_equals_two() -> None:
    source = ContextlessSource(range(5))
    for _ in range(2):
        source.get_one()
    assert source.nr_yielded == 2


def test_if_request_from_iterator_then_yield_iterator_contents() -> None:
    data = [0, 1, 2]
    source = ContextlessSource(iter(data))
    values = [source.get_one() for _ in range(len(data))]
    assert values == data


def test_if_request_from_tuple_then_yield_tuple_contents() -> None:
    data = [0, 1, 2]
    source = ContextlessSource(tuple(data))
    values = [source.get_one() for _ in range(len(data))]
    assert values == data


def test_if_request_from_list_then_yield_list_contents() -> None:
    data = [0, 1, 2]
    source = ContextlessSource(tuple(data))
    values = [source.get_one() for _ in range(len(data))]
    assert values == data


def test_if_request_from_range_then_yield_range_contents() -> None:
    data = [0, 1, 2]
    source = ContextlessSource(range(3))
    values = [source.get_one() for _ in range(len(data))]
    assert values == data


def test_if_request_too_many_then_raises_stopiteration() -> None:
    source = ContextlessSource(range(5))
    with pytest.raises(StopIteration):
        for _ in range(6):
            source.get_one()
