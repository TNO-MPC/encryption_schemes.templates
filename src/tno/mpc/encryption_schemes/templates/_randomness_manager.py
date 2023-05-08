"""
This module defines the protocol of a RandomnessSource, which yields randomness for a
RandomizedEncryptionScheme, and a RandomnessManager for orchestrating multiple such sources.
"""
from __future__ import annotations

import bisect
import contextlib
import sys
from typing import Generic, TypeVar

if sys.version_info < (3, 8):
    from typing_extensions import Protocol
else:
    from typing import Protocol

PYTHON_GE_310 = sys.version_info >= (3, 10)

RR = TypeVar("RR")  # Raw randomness
RR_co = TypeVar("RR_co", covariant=True)


class PauseIteration(StopIteration):
    """
    Source is (temporarily) out of randomness, but should not be closed.
    """


class RandomnessSource(Protocol[RR_co]):
    """
    Source of randomness for a RandomizedEncryptionScheme.
    """

    def open(self) -> None:
        """
        Open the source.
        """

    def get_one(self) -> RR_co:
        """
        Give one random value.

        :raise PauseIteration: Source is depleted but remains active.
        :raise StopIteration: Source is depleted and can be closed.
        """

    @property
    def nr_yielded(self) -> int:
        """
        Number of random values yielded.

        Equivalently, number of successful calls to self.get_one().
        """

    def close(self) -> None:
        """
        Close the source gracefully.
        """


SourceID = int


class RandomnessManager(Generic[RR_co]):
    """
    Object for obtaining randomness from various sources.

    The RandomnessManager can register sources of randomness, open and close them, and prioritize the order in which they are queried.
    """

    def __init__(self) -> None:
        """
        Initialize a new RandomnessManager.
        """
        self._sources: list[RandomnessSource[RR_co]] = []
        self._source_priority: dict[SourceID, int] = {}
        self._active_sources: list[SourceID] = []

        self._nr_yielded = 0

    @property
    def sources(self) -> tuple[RandomnessSource[RR_co], ...]:
        """
        Listing of available sources, sorted on order of decreasing priority.

        :return: Listing of available sources.
        """
        return tuple(self._sources)

    @property
    def nr_yielded(self) -> int:
        """
        Count of randomness yielded thus far.

        :return: Count of yielded randomness.
        """
        return self._nr_yielded

    def register_source(
        self,
        source: RandomnessSource[RR_co],
        priority: int = 100,
        boot_now: bool = False,
    ) -> None:
        """
        Register a source of randomness.

        :param source: Object that provides randomness.
        :param priority: Priority of the source. Randomness is requested from sources in order of
            decreasing priority. If another source of the same priority already exists, it is
            accessed before new sources with that priority.
        :param boot_now: If True, the source is opened immediately. If False, the source is opened
            the first time it is accessed.
        """
        if boot_now:
            self._open_source(source)
        self._source_priority[id(source)] = priority
        self._insert_source(source)

    def _insert_source(self, source: RandomnessSource[RR_co]) -> None:
        """
        Insert source into the existing sequence of sources in accordance with its priority.

        :param source: Source to be inserted.
        """
        if PYTHON_GE_310:
            bisect.insort_right(
                self._sources, source, key=lambda x: -self._source_priority[id(x)]
            )
        else:
            insert_id = bisect.bisect_right(
                [-self._source_priority[id(x)] for x in self._sources],
                -self._source_priority[id(source)],
            )
            self._sources = (
                self._sources[:insert_id] + [source] + self._sources[insert_id:]
            )

    def _open_source(self, source: RandomnessSource[RR_co]) -> None:
        """
        Open a source.

        :param source: Source to open.
        """
        source.open()
        self._set_active(source)

    def get_one(self) -> RR_co:
        """
        Yield a single random value.

        The random value is requested from registered sources in order of decreasing priority.

        If a queried source raises StopIteration, it is closed before the next source is queried.
        If the queried source raises PauseIteration, the next source is queried without further
        action. If an unopened source is to be queried for the first time, it is opened first.

        :raise StopIteration: The the available sources did not yield randomness.
        :raise ValueError: No sources have been registered.
        :return: Single random value.
        """
        if not self.sources:
            raise ValueError("No sources of randomness have been registered.")
        for source in self.sources:
            if not self._is_active(source):
                source.open()
                self._set_active(source)
            try:
                randomness = source.get_one()
            except PauseIteration:
                continue
            except StopIteration:
                self.unregister_source(source, do_close=True)
                continue
            self._nr_yielded += 1
            return randomness
        raise StopIteration("No source yielded randomness.")

    def _is_active(self, source: RandomnessSource[RR_co]) -> bool:
        """
        Indicate whether a source is currently active.

        :param source: Target source.
        :return: True if the source is active (open), False otherwise.
        """
        return id(source) in self._active_sources

    def _set_active(self, source: RandomnessSource[RR_co]) -> None:
        """
        Indicate that a source is now active.

        :param source: Source that is now active.
        """
        self._active_sources.append(id(source))

    def update_priority(self, source: RandomnessSource[RR_co], priority: int) -> None:
        """
        Change the priority of a registered source.

        If there are other sources with the same (updated) priority, they will be queried before
        the target source. This also happens if the updated priority is equal to the current
        priority.

        :param source: Source whose priority is updated.
        :param priority: New priority.
        """
        self._source_priority[id(source)] = priority
        self._sources.remove(source)
        self._insert_source(source)

    def unregister_source(
        self, source: RandomnessSource[RR_co], do_close: bool = True
    ) -> None:
        """
        Unregister a source object.

        :param source: Source to be unregistered.
        :param do_close: Close the source before unregistering it.
        """
        if do_close:
            self._active_sources.remove(id(source))
            source.close()
        self._sources.remove(source)
        del self._source_priority[id(source)]

    def shutdown(self) -> None:
        """
        Close and unregister all active sources.
        """
        with contextlib.ExitStack() as stack:
            for source in (src for src in self.sources if self._is_active(src)):
                stack.callback(self.unregister_source, source=source, do_close=True)

    def __del__(self) -> None:
        """
        Delete the object gracefully.
        """
        self.shutdown()
