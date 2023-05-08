"""
Object that provides randomness from a file.
"""
from __future__ import annotations

import sys
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Thread
from types import TracebackType
from typing import Callable, Iterable, cast, overload

from tenacity import Retrying, retry, retry_if_exception_type, stop_after_attempt

from tno.mpc.encryption_schemes.templates._randomness_manager import (
    RR,
    RandomnessSource,
)

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

DEFAULT_QUEUE_SIZE = 1_000


# Inherit from protocol for earlier detection of erroneous type annotations.
class FileSource(RandomnessSource[RR]):
    """
    Object for providing randomness from a file.

    Implements tno.mpc.encryption_schemes.templates._randomness_manager.RandomnessSource.
    """

    @overload
    def __init__(
        self,
        path: Path,
        delimiter: str = ...,
        queue_size: int = ...,
        queue: Queue[RR] | None = ...,
        retry_attempts: int = ...,
        retry_wait_s: float | None = ...,
        debug: bool = ...,
        *,
        deserializer: Callable[[str], RR],
    ) -> None:
        ...

    @overload
    def __init__(
        self: FileSource[int],
        path: Path,
        delimiter: str = ...,
        queue_size: int = ...,
        queue: Queue[RR] | None = ...,
        retry_attempts: int = ...,
        retry_wait_s: float | None = ...,
        debug: bool = ...,
    ) -> None:
        ...

    def __init__(
        self: FileSource[RR],
        path: Path,
        delimiter: str = ",",
        queue_size: int = DEFAULT_QUEUE_SIZE,
        queue: Queue[RR] | None = None,
        retry_attempts: int = 3,
        retry_wait_s: float | None = 1,
        debug: bool = False,
        *,
        deserializer: Callable[[str], RR] | None = None,
    ) -> None:
        """
        Object that reads randomness from files.

        :param path: Path to file containing randomness.
        :param delimiter: Separator between random numbers in the file.
        :param queue_size: Maximum number of elements that can be put in the queue. Ignored if
            argument queue is also provided.
        :param queue: Queue to use for storing randomness from files.
        :param retry_attempts: Number of attempts to get random value from the queue.
        :param retry_wait_s: Number of seconds to wait between attempts to get random value from
            the queue. If None, wait until a value is yielded (e.g. wait=infinity).
        :param debug: Flag to determine whether debug information should be displayed.
        :param deserializer: Function for converting string from provided file into randomness
            object. Defaults to built-in "int" function.
        :raise TypeError: Argument to path is of incorrect type.
        """
        if not isinstance(path, Path):
            raise TypeError(
                f"Expected path of type Path, but received type {type(path)}."
            )
        self._path = path
        self._delimiter = delimiter
        self._queue = queue or Queue(maxsize=queue_size)
        self._retry_attempts = retry_attempts
        self._retry_wait_s = retry_wait_s

        self._shutdown = Event()
        self._file_thread: Thread | None = None

        self.deserializer: Callable[[str], RR] = (
            # By the overloads, we can only pass None in the case where RR = int
            cast(Callable[[str], RR], int)
            if deserializer is None
            else deserializer
        )

        self._nr_yielded = 0
        self._debug = debug

    @property
    def path(self) -> Path:
        """
        Path to file that is read for randomness.

        :return: Path to file.
        """
        return self._path

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

    def open(self) -> None:
        """
        Boot thread to read file.
        """
        file_thread = Thread(
            target=self._file_thread_fn, daemon=False, args=(self.path, self._queue)
        )
        file_thread.start()
        self._file_thread = file_thread

    def get_one(self) -> RR:
        """
        Get one random value.

        :raise StopIteration: Randomness queue is empty and no active file thread remain.
        :raise TimeoutError: Randomness queue is empty and active file thread does not put new values into it.
        :raise ValueError: No threads instantiated for reading file.
        :return: One random value.
        """
        if self._file_thread is None:
            raise ValueError(
                "Attempted to read randomness from file, but file thread was not instantiated. "
                "Make sure to first call FileSource.open()."
            )
        try:
            for attempt in Retrying(
                stop=stop_after_attempt(self._retry_attempts),
                retry=retry_if_exception_type(Empty),
                reraise=True,
            ):
                # The file thread may still be closing, so make sure to retry that as well.
                if not self._file_thread.is_alive() and self._queue.empty():
                    raise StopIteration(
                        "File-reading thread is closed and queue is empty, so this source is "
                        "depleted."
                    )
                with attempt:
                    value = self._queue.get(timeout=self._retry_wait_s)
        except Empty:
            raise TimeoutError(  # pylint: disable=raise-missing-from
                "Received no value from file thread before timeout."
            )
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
        Shuts down all file reading threads.
        """
        if self._file_thread is not None:
            self._shutdown.set()
            self._file_thread.join()
            self._shutdown.clear()

    def _file_thread_fn(self, path: Path, file_queue: Queue[RR | Exception]) -> None:
        """
        Function to be run by the file worker. The file is read in chunks and these chunks are then
        used to extract random elements.

        :param path: path of the file with randomness for the file worker
        :param file_queue: queue to store files in
        """

        class ShutDownError(Exception):
            """
            Inappropriate action by process that should shut down.
            """

        @retry(retry=retry_if_exception_type(Full))
        def safe_add_randomness(randomness: RR) -> None:
            """
            Add provided elements to queue while watching shutdown event.

            :param randomness: Element to be added.
            :raise ShutDownError: Raised when thread is signalled to stop.
                Element will not be added.
            """
            if self._shutdown.is_set():
                self._safe_print(
                    f"[filethread, path: {path}] shutdown signal received "
                    f"- shutting down.."
                )
                raise ShutDownError
            file_queue.put(randomness, timeout=0.01)

        def add_randomnesses_to_iterator(randomnesses: Iterable[RR]) -> None:
            """
            Add provided elements to the stored (future) randomizations.

            :param randomnesses: Elements to be added.
            :raise ShutDownError: Raised when thread is signalled to stop.
                Elements will not be added.
            """
            for rand in randomnesses:
                self._safe_print("[filethread] checking shutdown before adding")
                safe_add_randomness(rand)
            self._safe_print(
                f"[filethread, path: {path}] successfully added randomness"
            )

        self._safe_print(f"[filethread, path: {path}] initialized")
        last_partial_chunk = ""
        with path.open("r", buffering=4096) as file:
            try:
                for new_chunk in file:
                    chunk = last_partial_chunk + new_chunk
                    # split the buffer on the separator
                    splitted_chunk = chunk.split(self._delimiter)
                    # the last part of the split buffer is (most likely) not read entirely so store
                    # that in the buffer
                    last_partial_chunk = splitted_chunk.pop()

                    # add the other random values to the list
                    randomnesses = (
                        self.deserializer(randomness) for randomness in splitted_chunk
                    )
                    add_randomnesses_to_iterator(randomnesses)

                # EOF reached
                # the last value in the buffer is still one random value, so add that to the
                # list
                if last_partial_chunk:
                    add_randomnesses_to_iterator(
                        [self.deserializer(last_partial_chunk)]
                    )
            except ShutDownError:
                pass
        self._safe_print(f"[filethread, path: {path}] FINISHED")

    def _safe_print(self, message: str) -> None:
        """
        Atomic print. It does nothing if the debug flag is False

        :param message: message to be printed.
        """
        if not self._debug:
            return

        print(message, flush=True)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}(path={self._path})"
