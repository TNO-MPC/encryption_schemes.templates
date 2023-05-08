"""
Object for providing randomness from a source that does not need to be opened or closed.
"""
from typing import Iterable

from tno.mpc.encryption_schemes.templates._randomness_manager import (
    RR,
    RandomnessSource,
)


# Inherit from protocol for earlier detection of erroneous type annotations.
class ContextlessSource(RandomnessSource[RR]):
    """
    Object for providing randomness from a contextless source, e.g. a source that does not need to
    be opened or closed.

    Implements tno.mpc.encryption_schemes.templates._randomness_manager.RandomnessSource.
    """

    def __init__(
        self,
        values: Iterable[RR],
    ) -> None:
        """
        Object that yields randomness from the provided iterable.

        :param values: Iterable that yields random values one at a time.
        """
        self._randomness = iter(values)
        self._nr_yielded = 0

    def open(self) -> None:
        """
        Dummy function as contextless sources do not need to be opened.
        """

    def get_one(self) -> RR:
        """
        Get one random value.

        :return: One random value.
        """
        value = next(self._randomness)
        self._nr_yielded += 1
        return value

    @property
    def nr_yielded(self) -> int:
        """
        Number of random elements yielded.

        :return: Number of random elements yielded.
        """
        return self._nr_yielded

    def close(self) -> None:
        """
        Dummy function as contextless sources do not need to be opened.
        """

    def __str__(self) -> str:
        return f"{self.__class__.__name__}"
