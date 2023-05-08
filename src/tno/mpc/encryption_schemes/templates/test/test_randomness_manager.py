"""
File containing all tests related to the RandomnessManager.
"""
# pylint: disable=missing-function-docstring
from itertools import repeat
from typing import Iterable

import pytest

from tno.mpc.encryption_schemes.templates._randomness_manager import RandomnessManager
from tno.mpc.encryption_schemes.templates.random_sources import ContextlessSource


class OpenableRandomnessSource(ContextlessSource[int]):
    """
    Wrapped contextless source that registers whether it is opened and closed.
    """

    def __init__(self, values: Iterable[int] = (1,)) -> None:
        super().__init__(values)
        self.was_opened = False
        self.was_closed = False

    def open(self) -> None:
        """
        Register that the source is opened.
        """
        self.was_opened = True

    def close(self) -> None:
        """
        Register that the source is closed.
        """
        self.was_closed = True


class UnclosableRandomnessSource(OpenableRandomnessSource):
    """
    Wrapped OpenableRandomnessSource that throws a ValueError when closed.
    """

    def close(self) -> None:
        """
        Throws an error when closing.

        :raise ValueError: Always.
        """
        raise ValueError("I cannot be closed!!")


def get_source_empty() -> OpenableRandomnessSource:
    """
    Get an empty source of randomness.

    :return: Source of randomness.
    """
    return OpenableRandomnessSource([])


def get_source_finite_ones() -> OpenableRandomnessSource:
    """
    Get a one-element source of randomness.

    :return: Source of randomness.
    """
    return OpenableRandomnessSource([1])


def get_source_finite_twos() -> OpenableRandomnessSource:
    """
    Get a two-element source of randomness.

    :return: Source of randomness.
    """
    return OpenableRandomnessSource([2, 2])


def get_source_infinite_threes() -> OpenableRandomnessSource:
    """
    Get an infinite source of randomness.

    :return: Source of randomness.
    """
    return OpenableRandomnessSource(repeat(3))


def test_when_no_sources_registered_if_get_one_then_raise_valueerror() -> None:
    manager: RandomnessManager[int] = RandomnessManager()
    with pytest.raises(ValueError):
        manager.get_one()


def test_if_source_registered_then_get_one_yields_value() -> None:
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(get_source_finite_ones())
    assert manager.get_one() == 1


def test_when_source_registered_and_empty_if_get_one_then_raise_stopiteration() -> None:
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(get_source_finite_ones())
    manager.get_one()
    with pytest.raises(StopIteration):
        manager.get_one()


def test_if_request_two_then_nr_yielded_equals_two() -> None:
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(get_source_infinite_threes())

    for _ in range(5):
        manager.get_one()
    assert manager.nr_yielded == 5


def test_when_source_registered_if_register_low_priority_source_then_listed_later_in_sources() -> (
    None
):
    manager: RandomnessManager[int] = RandomnessManager()
    source_ones = get_source_finite_ones()
    source_twos = get_source_finite_twos()
    manager.register_source(source_ones, priority=100)
    manager.register_source(source_twos, priority=0)
    assert manager.sources == (source_ones, source_twos)


def test_when_source_registered_if_register_high_priority_source_then_listed_earlier_in_sources() -> (
    None
):
    manager: RandomnessManager[int] = RandomnessManager()
    source_ones = get_source_finite_ones()
    source_twos = get_source_finite_twos()
    manager.register_source(source_ones, priority=100)
    manager.register_source(source_twos, priority=1_000)
    assert manager.sources == (source_twos, source_ones)


def test_when_same_priority_sources_registered_if_get_one_then_yields_from_first_source() -> (
    None
):
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(get_source_finite_ones())
    manager.register_source(get_source_finite_twos())
    assert manager.get_one() == 1


def test_when_different_priority_sources_registered_if_get_one_then_yields_from_highest_priority_source() -> (
    None
):
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(get_source_finite_ones(), priority=100)
    manager.register_source(get_source_finite_twos(), priority=1_000)
    assert manager.get_one() == 2


def test_when_two_sources_registered_if_one_depletes_then_manager_yields_from_other_source() -> (
    None
):
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(get_source_finite_ones())
    manager.register_source(get_source_finite_twos())
    values = [manager.get_one() for _ in range(3)]
    assert values == [1, 2, 2]


def test_if_priority_updated_to_same_value_then_lowest_source_of_that_priority() -> (
    None
):
    manager: RandomnessManager[int] = RandomnessManager()
    source_ones = get_source_finite_ones()
    source_twos = get_source_finite_twos()
    manager.register_source(source_ones, priority=100)
    manager.register_source(source_twos, priority=100)

    manager.update_priority(source_ones, priority=100)
    assert manager.sources == (source_twos, source_ones)


def test_when_two_sources_registered_if_priority_updated_then_yield_from_highest_priority_source() -> (
    None
):
    manager: RandomnessManager[int] = RandomnessManager()
    source_threes = get_source_infinite_threes()
    source_ones = get_source_finite_ones()
    manager.register_source(source_threes, priority=100)
    manager.register_source(source_ones, priority=10)

    values = [manager.get_one()]
    manager.update_priority(source_ones, 1_000)
    values.append(manager.get_one())
    assert values == [3, 1]


def test_when_two_sources_registered_if_unregister_source_then_yield_from_other_source() -> (
    None
):
    manager: RandomnessManager[int] = RandomnessManager()
    source_threes = get_source_infinite_threes()
    manager.register_source(source_threes)
    manager.register_source(get_source_finite_ones())

    values = [manager.get_one()]
    manager.unregister_source(source_threes)
    values.append(manager.get_one())
    assert values == [3, 1]


def test_if_source_depleted_then_source_removed() -> None:
    source_empty = OpenableRandomnessSource([])
    source_ones = get_source_finite_ones()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source_empty)
    manager.register_source(source_ones)

    manager.get_one()
    assert manager.sources == (source_ones,)


def test_if_source_depleted_then_source_closed() -> None:
    source_empty = OpenableRandomnessSource([])
    source_ones = get_source_finite_ones()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source_empty)
    manager.register_source(source_ones)

    manager.get_one()
    assert source_empty.was_closed


def test_if_register_source_without_boot_now_then_source_not_opened() -> None:
    source = get_source_empty()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source, boot_now=False)
    assert not source.was_opened


def test_if_register_source_with_boot_now_then_source_opened() -> None:
    source = get_source_empty()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source, boot_now=True)
    assert source.was_opened


def test_if_unregister_source_without_do_close_then_source_not_closed() -> None:
    source = get_source_empty()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source)
    manager.unregister_source(source, do_close=False)
    assert not source.was_closed


def test_if_unregister_source_with_do_close_then_source_closed() -> None:
    source = get_source_empty()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source, boot_now=True)
    manager.unregister_source(source, do_close=True)
    assert source.was_closed


def test_when_closed_source_registered_if_get_one_then_source_opened() -> None:
    source = get_source_finite_ones()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source, boot_now=False)
    manager.get_one()
    assert source.was_opened


def test_when_open_source_registered_if_manager_shutdown_then_source_closed() -> None:
    source = get_source_empty()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source, boot_now=True)
    manager.shutdown()
    assert source.was_closed


def test_when_closing_source_throws_exception_then_all_other_sources_are_closed_regardless() -> (
    None
):
    source_1 = get_source_empty()
    source_unclosable = UnclosableRandomnessSource()
    source_2 = get_source_empty()
    manager: RandomnessManager[int] = RandomnessManager()
    manager.register_source(source_1, boot_now=True)
    manager.register_source(source_unclosable, boot_now=True)
    manager.register_source(source_2, boot_now=True)

    with pytest.raises(ValueError):
        manager.shutdown()

    assert source_1.was_closed
    assert source_2.was_closed
