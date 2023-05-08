"""
Object that provides randomness from processes.
"""
from __future__ import annotations

import sys
import time
from concurrent.futures import Future, ProcessPoolExecutor, as_completed
from itertools import chain
from types import TracebackType
from typing import Any, Callable, Iterable, Iterator, List

from tno.mpc.encryption_schemes.templates._randomness_manager import (
    RR,
    PauseIteration,
    RandomnessSource,
)

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

PYTHON_GE_39 = sys.version_info >= (3, 9)


class FakeList(List[Any]):
    """
    List that completely discards anything you may want to add.
    """

    def __init__(self, items: Iterable[Any] = (None,)) -> None:
        pass

    def extend(self, values: Iterable[Any]) -> None:
        pass


# Inherit from protocol for earlier detection of erroneous type annotations.
class ProcessSource(RandomnessSource[RR]):
    """
    Object for providing randomness from processes that repeatedly execute a randomness
    generating function.

    Implements tno.mpc.encryption_schemes.templates._randomness_manager.RandomnessSource.
    """

    def __init__(
        self,
        generation_function: Callable[[], RR],
        amount: int = 0,
        max_workers: int | None = None,
        debug: bool = False,
    ) -> None:
        """
        Object that starts processes to generate and yield random values.

        This construction starts generation workers that generate new randomness using the given
        generation function. This happens in separate processes to avoid blocking and speed up the
        generation.

        :param generation_function: Unbound callable object (e.g. function or static method) that
            generates one random value.
        :param amount: Upper bound on the total amount of randomizations to generate.
        :param max_workers: Number of workers that generate randomizations in parallel. Should be
            at least 1. If None, the number of workers equals the number of CPUs on the device.
        :param debug: Flag to determine whether debug information should be displayed.
        """
        self._generation_function = generation_function
        self._nr_requested = amount
        self._nr_yielded = 0
        if max_workers is not None and max_workers < 1:
            raise ValueError(
                "Requires at least one worker to generate randomness, but "
                f"max_workers={max_workers}."
            )
        self._max_workers = max_workers
        self._pool: ProcessPoolExecutor | None = None
        # keep track of futures in python<3.9 to cancel them manually later
        self._futures: list[Future[RR]] = FakeList() if PYTHON_GE_39 else []
        self._randomness: Iterator[Future[RR]] = iter([])

        self._debug = debug

    @property
    def nr_requested(self) -> int:
        """
        Number of random elements requested.

        :return: Number of random elements requested.
        """
        return self._nr_requested

    @property
    def nr_yielded(self) -> int:
        """
        Number of random elements yielded.

        :return: Number of random elements yielded.
        """
        return self._nr_yielded

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def pool(self) -> ProcessPoolExecutor:
        """
        Get the pool of the ProcessSource.

        :raise ValueError: No pool has yet been initialized.
        :return: Pool of the current object.
        """
        if self._pool is None:
            raise ValueError("No pool has yet been initialized")
        return self._pool

    def open(self) -> None:
        """
        Instantiate a pool for processes and set them to work.
        """
        self._pool = ProcessPoolExecutor(max_workers=self._max_workers)
        self._submit_to_pool(self.nr_requested)

    def get_one(self) -> RR:
        """
        Get one random value.

        :raise PauseIteration: All requested randomness was already yielded.
        :raise ValueError: No pool of processes instantiated.
        :return: Single random value.
        """
        if self._pool is None:
            raise ValueError(
                "Attempted to read randomness from pool, but pool was not instantiated. Make "
                "sure to first call ProcessSource.open()."
            )

        try:
            randomness = next(self._randomness).result()
        except StopIteration:
            raise PauseIteration(  # pylint: disable=raise-missing-from
                "Process source is depleted. More randomness can be required through "
                "ProcessSource.increase_requested."
            )
        self._nr_yielded += 1
        return randomness

    def close(self) -> None:
        """
        Shuts down all processes.
        """
        if PYTHON_GE_39:
            self.pool.shutdown(wait=False, cancel_futures=True)
        else:
            # For python<3.9, concurrent.futures.ProcessPoolExecutor.shutdown() does not
            # accept the cancel_futures but instead awaits completion of all scheduled Futures.
            # We instead store the futures and cancel them manually. Then we await the result
            # to prevent hanging (tests) after shutdown.
            #
            # The pool shutdown may hang if futures are created and cancelled immediately after. We
            # introduce a short delay to prevent the hang
            # (https://github.com/python/cpython/issues/94440).
            time.sleep(0.001)
            for fut in self._futures:
                fut.cancel()
            self.pool.shutdown(wait=True)

    def increase_requested(self, amount: int) -> None:
        """
        Increase the amount of randomness to be generated by the process pool.

        :param amount: Amount to be generated additionally.
        """
        if self._pool is not None:
            self._submit_to_pool(amount)
        self._nr_requested += amount

    def _submit_to_pool(self, amount: int) -> None:
        """
        Require the pool to generate more randomness.

        :param amount: Amount of randomness to be generated additionally.
        """
        futures = [self.pool.submit(self._generation_function) for _ in range(amount)]
        self._futures.extend(futures)
        self._randomness = chain(self._randomness, as_completed(futures))

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__}(nr_workers={self._max_workers}, "
            f"nr_requested={self.nr_requested})"
        )
