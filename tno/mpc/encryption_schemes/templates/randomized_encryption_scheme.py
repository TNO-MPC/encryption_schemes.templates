"""
Generic classes for creating an EncryptionScheme that allows for precomputed, or stored randomness.
"""

import warnings
from abc import ABC, abstractmethod
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread
from typing import Any, Callable, List, Optional, TypeVar, Union, cast

from .encryption_scheme import (
    CV,
    KM,
    PT,
    RP,
    Ciphertext,
    EncodedPlaintext,
    EncryptionScheme,
)


class Randomness:
    """
    Object containing precomputed randomness. This randomness is either stored internally
    or in a specified file. Allows for functionality to create randomness on-the-fly.
    """

    # default variable that ensures that every <default_shutdown_timeout> seconds, each thread
    # checks for a shutdown signal for graceful termination
    default_shutdown_timeout = 0.01

    def __init__(
        self,
        generation_function: Callable[[], int],
        randomizations: Optional["Queue[int]"] = None,
        max_size: int = 100,
        total: Optional[int] = None,
        nr_of_threads: int = 1,
        path: Optional[str] = None,
        separator: str = ",",
        start_generation: bool = True,
        debug: bool = False,
    ) -> None:
        """
        Construct a Randomness object. This construction starts generation workers and a file worker
        that generate new randomness using the given generation function and abstract random from a
        file respectively. This happens in separate threads and the random elements are placed in a
        (thread-safe) queue. This queue can then be used to request random elements at encryption
        time.

        :param debug: flag to determine whether debug information should be displayed.
        :param start_generation: flag to determine whether all threads should immediately start
            generating randomness.
        :param max_size: maximum size of the buffer of randomizations.
        :param total: upper bound on the total amount of randomizations to generate.
        :param nr_of_threads: number of threads that generate randomizations in parallel.
        :param generation_function: Function that generates one random value.
        :param randomizations: Precomputed in-memory randomness to be stored in this object for
            usage in an encryption scheme.
        :param path: Optional path to a file containing randomness.
        :param separator: Separator between random numbers in the file.
        """
        if randomizations is None:
            randomizations = Queue(max_size)
        self._generation_function = generation_function
        self.total = total
        self.nr_of_threads = nr_of_threads
        self.randomizations = randomizations
        self.has_buffer = self.randomizations.qsize() > 0
        self.path = path
        self.file_position = 0
        self.delimiter = separator
        self.debug = debug

        self.print_lock = Lock()
        self.count_lock = Lock()

        self._generating = Event()
        self._shutdown = Event()

        self.has_file = path is not None
        # variable that saves part of the file containing randomizations
        self._chunk = ""

        self.generation_threads: List[Thread] = []
        self.file_thread: Optional[Thread] = None

        # variable that saves the position in the file we were reading
        self._file_position = 0

        # variable that keeps track of the number of generated randomizations
        self.generated_randomizations = 0

        # set up threads that generate randomizations and place them in the appropriate queue
        self.boot_generation(nr_of_threads, path, start_generation)

    def _safe_increment_count(self) -> None:
        """
        Atomic increment of generated randomizations count.
        """
        if self.total is not None:
            self.count_lock.acquire()
            self.generated_randomizations += 1
            if self.generated_randomizations == self.total:
                self.stop_generating()
            elif self.generated_randomizations > self.total + self.nr_of_threads:
                warnings.warn(
                    f"Requested {self.generated_randomizations} random elements, "
                    f"however randomness generation is bounded by {self.total}."
                )
            self.count_lock.release()

    def safe_print(self, message: str) -> None:
        """
        Atomic print. It does nothing if the debug flag is False

        :param message: message to be printed.
        """
        if not self.debug:
            return

        self.print_lock.acquire()
        print(message)
        self.print_lock.release()

    def boot_generation(
        self,
        nr_of_threads: Optional[int] = None,
        path: Optional[str] = None,
        start_generation: bool = True,
    ) -> None:
        """
        Shut down the generation threads and file thread if they are still running.
        Then, initialize new generation threads and a file thread.

        :param nr_of_threads: number of generation threads.
            (Default: None, the nr_of_threads parameter is taken from the original __init__)
        :param path: path to the file containing randomizations.
            (Default: None, the path parameter is taken from the original __init__)
        :param start_generation: flag that determines whether the threads start generating
            immediately.
        """
        # check if there are still live threads
        if len(self.generation_threads) > 0 or self.file_thread is not None:
            self.safe_print("\n=== REBOOTING ===\n")
            self.shut_down()

        self.safe_print("\n=== BOOTING UP ===\n")

        # default the nr_of_threads parameter to the one specified in __init__
        if nr_of_threads is None:
            nr_of_threads = self.nr_of_threads

        # default the path parameter to the one specified in __init__
        if path is not None:
            self.path = path
            self.has_file = True

        # set up a thread to read randomizations from a file if provided
        if self.path is not None:
            self.file_thread = Thread(target=self.file_worker, daemon=False)
            self.file_thread.start()

        # set up generation threads
        self.generation_threads = [
            Thread(target=self.generation_worker, daemon=True, args=(i,))
            for i in range(nr_of_threads)
        ]
        for thread in self.generation_threads:
            thread.start()

        if start_generation:
            self.start_generating()

    def start_generating(self) -> None:
        """
        Turn on the signal that tells the threads to start generating randomness.
        """
        if not self._generating.is_set():
            self.safe_print("\n=== generation signal: ON ===\n")
            self._generating.set()

    def stop_generating(self) -> None:
        """
        Tell the threads that they can stop generating randomness.
        """
        if self._generating.is_set():
            self.safe_print("\n=== generation signal: OFF ===\n")
            self._generating.clear()

    def shut_down(self) -> None:
        """
        Turn on the signal that tells the threads to drop what they're doing and shut down.
        """
        self.safe_print("\n=== SHUTDOWN INITIATED ===\n")
        # set the stop generating and shutdown flags
        self.stop_generating()
        self._shutdown.set()

        # wait until the threads have registered the signal and gracefully returned
        for thread in self.generation_threads:
            thread.join()
        if self.file_thread is not None:
            self.file_thread.join()

        # clear the flag
        self._shutdown.clear()

        # clear the threads
        self.generation_threads = []
        self.file_thread = None

    def add_generation_worker(self) -> None:
        """
        Add an extra thread that generates randomness.
        """
        identifier = len(self.generation_threads)
        thread = Thread(target=self.generation_worker, args=(identifier,), daemon=False)
        thread.start()
        self.generation_threads.append(thread)

    def file_worker(self) -> None:
        """
        Function to be run by the file worker. The file is read in chunks and these chunks are then
        used to extract random elements.
        """
        self.safe_print("[filethread] initialized")
        chunk = self._chunk
        assert self.path is not None
        file = open(self.path, "r")
        new_chunk = file.read(4096)
        while new_chunk:
            # if the signal for generating is not set, we wait until it is set again
            # the wait command is blocking, so we need to periodically check for shutdown signals
            blocked = True
            while blocked:
                self.safe_print("[filethread] checking shutdown")
                if self._shutdown.is_set():
                    self.safe_print(
                        "[filethread] shutdown signal received (waiting) - shutting down.."
                    )
                    file.close()
                    return

                blocked = not self._generating.wait(
                    timeout=Randomness.default_shutdown_timeout
                )
                if blocked:
                    self.safe_print(
                        "[filethread] generation blocked - waiting for signal"
                    )

            chunk += new_chunk
            # split the buffer on the separator
            split_chunk = chunk.split(self.delimiter)
            # the last part of the split buffer is (most likely) not read entirely so store
            # that in the buffer
            chunk = split_chunk.pop()

            # add the other random values to the list
            for randomization in split_chunk:
                # the put command can block, so we need to periodically check for shutdown signals
                int_randomization = int(randomization)
                keep_trying = True
                while keep_trying:
                    try:
                        self.safe_print("[filethread] checking shutdown before adding")
                        if self._shutdown.is_set():
                            self.safe_print(
                                "[filethread] shutdown signal received (buffer full) - "
                                "shutting down.."
                            )
                            self._chunk = chunk
                            file.close()
                            return
                        self.safe_print("[filethread] trying to add to queue")
                        self.randomizations.put(
                            int_randomization,
                            timeout=Randomness.default_shutdown_timeout,
                        )
                        self.safe_print("[filethread] added successfully")
                        keep_trying = False
                    except Full:
                        self.safe_print("[filethread] buffer is full - retrying")

            new_chunk = file.read(4096)

        # EOF reached
        # the last value in the buffer is still one random value, so add that to the
        # list
        self.safe_print("[filethread] EOF reached")
        # the put command can block, so we need to periodically check for shutdown signals

        int_randomization = int(chunk)
        keep_trying = True
        while keep_trying:
            try:
                self.safe_print("[filethread] after EOF | checking shutdown")
                if self._shutdown.is_set():
                    self.safe_print(
                        "[filethread] after EOF | shutdown signal received - shutting down.."
                    )
                    self.has_file = False
                    file.close()
                    return
                self.safe_print("[filethread] after EOF | trying to add to queue")
                self.randomizations.put(
                    int_randomization, timeout=Randomness.default_shutdown_timeout
                )
                self.has_file = False
                file.close()
                keep_trying = False
                self.safe_print("[filethread] FINISHED")
            except Full:
                self.safe_print("[filethread] after EOF | buffer is full - retrying")

    def generation_function(self) -> int:
        """
        Wrapper around generation function

        :return: random element
        """
        self._safe_increment_count()
        return self._generation_function()

    def generation_worker(self, identifier: int) -> None:
        """
        Function to be run by each generation worker. These workers keep generating random elements
        and try to add them to the queue until a stop sign is given.

        :param identifier: identifier used for debugging
        """
        self.safe_print(f"[workerthread {identifier}] initialized")
        while True:
            # if the signal for generating is not set, we wait until it is set again
            # the wait command is blocking, so we need to periodically check for shutdown signals
            blocked = True
            while blocked:
                self.safe_print(
                    f"[workerthread {identifier}] checking shutdown (before waiting)"
                )
                if self._shutdown.is_set():
                    self.safe_print(
                        f"[workerthread {identifier}] shutdown signal received (waiting)"
                    )
                    return
                blocked = not self._generating.wait(Randomness.default_shutdown_timeout)
                if blocked:
                    self.safe_print(
                        f"[workerthread {identifier}] generation blocked - waiting for signal"
                    )

            randomization = self.generation_function()

            # the put command can block, so we need to periodically check for shutdown signals
            keep_trying = True
            while keep_trying:
                self.safe_print(
                    f"[workerthread {identifier}] checking shutdown (before adding)"
                )
                if self._shutdown.is_set():
                    self.safe_print(
                        f"[workerthread {identifier}] shutdown signal received - shutting down.."
                    )
                    return
                try:
                    self.safe_print(
                        f"[workerthread {identifier}] trying to add to queue"
                    )
                    self.randomizations.put(
                        randomization, timeout=Randomness.default_shutdown_timeout
                    )
                    self.safe_print(f"[workerthread {identifier}] added successfully")
                    keep_trying = False
                except Full:
                    self.safe_print(
                        f"[workerthread {identifier}] buffer is full - retrying"
                    )

    def __len__(self) -> int:
        """
        Determine number of randomizations currently present in the queue.

        :return: Number of randomizations currently present in the queue.
        """
        return self.randomizations.qsize()

    def get_one(self) -> int:
        """
        Checks the buffer for random value. If the buffer is empty, it waits for a random value
        from the generation thread.

        :return: One random element.
        """
        if len(self) == 0:
            if not self.has_file and len(self.generation_threads) == 0:
                # no threads that generate randomness
                return self.generation_function()
            if not self._generating.is_set():
                # there are threads, but they are not generating
                return self.generation_function()
            # There are threads and they are generating, so we try to get a randomization
            # (hopefully this will be generated within 0.1 seconds)

        # There is an overwhelming probability that there is a randomization available
        # (the queue size is not 0) or there will be a randomization available soon
        # (the queue size was 0 but we are still generating). However, because Queue.qsize()
        # can be inaccurate due to multithreading, so even if the queue size says it is not 0, we
        # still need to check using a timeout.
        try:
            randomization = self.randomizations.get(timeout=0.1)
            return randomization
        except Empty:
            return self.generation_function()


RC = TypeVar("RC", bound="RandomizableCiphertext[Any, Any, Any, Any]")


class RandomizableCiphertext(Ciphertext[KM, PT, RP, CV], ABC):
    """
    Ciphertext that can be rerandomized. Subclass of Ciphertext.
    """

    def __init__(
        self: RC,
        raw_value: Any,
        scheme: "RandomizedEncryptionScheme[KM, PT, RP, CV, RC]",
        *,
        fresh: bool = False,
    ) -> None:
        """
        Construct a RandomizableCiphertext, with the given value for the given EncryptionScheme.

        :param raw_value: Ciphertext value.
        :param scheme: RandomizedEncryptionScheme that is used to encrypt this ciphertext.
        :param fresh: Indicates whether fresh randomness is already applied to the raw_value.
        :raise TypeError: When scheme has the incorrect type.
        """
        if not isinstance(scheme, RandomizedEncryptionScheme):
            raise TypeError(f"expected RandomizedEncryptionScheme, got {type(scheme)}")
        self._fresh = fresh
        super().__init__(raw_value, scheme)

    @property
    def value(self) -> CV:
        raise NotImplementedError(
            f"The raw value of {self.__class__.__name__} can be viewed through peek_value() or accessed via get_value(). The latter call also marks the ciphertext as not fresh."
        )

    def peek_value(self) -> CV:
        """
        Peek at the raw value of the ciphertext.

        Accessing this value does not change the freshness of the ciphertext. If this is not
        desired, call the get_value method.

        :return: Value of the ciphertext
        """
        return self._raw_value

    def get_value(self) -> CV:
        """
        Get the raw value of the ciphertext.

        Accessing this value marks the ciphertext as not fresh. If this is not desired, call the
        peek_value method.

        :return: Value of the ciphertext
        """
        self._fresh = False
        return self._raw_value

    @property
    def fresh(self: RC) -> bool:
        """
        Indicate whether the ciphertest has fresh randomness.

        Ciphertexts that are send to other parties should generally be fresh. This can be achieved
        by calling self.randomize().

        :return: True if the randomness is fresh, False otherwise.
        """
        return self._fresh

    def randomize(self: RC) -> RC:
        """
        Rerandomize this ciphertext object.

        :return: The rerandomized object (self).
        """
        randomization_value = cast(
            RandomizedEncryptionScheme[KM, PT, RP, CV, RC], self.scheme
        ).get_randomness()
        self.apply_randomness(randomization_value)
        self._fresh = True
        return self

    @abstractmethod
    def apply_randomness(self, randomization_value: Any) -> None:
        """
        Apply a random value to rerandomize this ciphertext.

        :param randomization_value: Random value used to rerandomize this ciphertext.
        :raise NotImplementedError: When scheme does not support rerandomization.
        """
        raise NotImplementedError()

    def __str__(self) -> str:
        """
        :return: String representation of RandomizedCiphertext.
        """
        return f"{self.__class__.__name__}<value={str(self.peek_value())}, fresh={self.fresh}>"


class RandomizedEncryptionScheme(EncryptionScheme[KM, PT, RP, CV, RC], ABC):
    """
    Abstract base class for a RandomizedEncryptionScheme. Subclass of EncryptionScheme
    """

    def __init__(
        self,
        randomizations: Optional["Queue[int]"] = None,
        max_size: int = 100,
        total: Optional[int] = None,
        nr_of_threads: int = 1,
        path: Optional[str] = None,
        separator: str = ",",
        start_generation: bool = True,
        debug: bool = False,
    ) -> None:
        """
        Initiate a Randomness variable with the given parameters to be used for
        randomizing ciphertexts.

        :param randomizations: queue with randomizations. If no queue is given, it creates a
            fresh one.
        :param max_size: maximum size of the queue.
        :param total: upper bound on the total amount of randomizations to generate.
        :param nr_of_threads: number of generation worker threads that should be started.
        :param path: path (including filename) to the file that contains randomizations.
            By default no path is given and no randomness is extracted from any files.
        :param separator: separator for the random values in the given file.
        :param start_generation: flag that determines whether the scheme starts generating
            randomness immediately.
        :param debug: flag to determine whether debug information should be displayed.
        """
        self.randomness: Randomness
        self.initialize_randomness(
            randomizations=randomizations,
            max_size=max_size,
            total=total,
            nr_of_threads=nr_of_threads,
            path=path,
            separator=separator,
            start_generation=start_generation,
            debug=debug,
        )
        EncryptionScheme.__init__(self)

    def initialize_randomness(
        self,
        **kwargs: Any,
    ) -> None:
        r"""
        Initializes a randomness class

        :param \**kwargs: keyword arguments to pass on to Randomness constructor
        """
        if hasattr(self, "randomness"):
            self.randomness.shut_down()
        self.randomness = Randomness(
            self.generate_randomness,
            **kwargs,
        )

    def get_randomness(self) -> int:
        """
        Get new randomness from the randomness source.

        :return: One random value.
        """
        return self.randomness.get_one()

    @abstractmethod
    def generate_randomness(self) -> int:
        """
        Method to generate randomness for this particular scheme.

        :raise NotImplementedError: When scheme does not support randomness generation.
        :return: A single random element with respect to the scheme.
        """
        raise NotImplementedError()

    def _encrypt_raw(self, plaintext: EncodedPlaintext[RP]) -> RC:
        return self._unsafe_encrypt_raw(plaintext).randomize()

    def unsafe_encrypt(
        self, plaintext: Union[PT, EncodedPlaintext[RP]], apply_encoding: bool = True
    ) -> RC:
        """
        Encrypts the entered (encoded) Plaintext, but does not apply randomness. Also encodes the
        Plaintext when this is required.

        :param plaintext: Plaintext or EncodedPlaintext to be encrypted.
        :param apply_encoding: Boolean indicating whether a non-encoded plaintext should be encoded.
            If False, the plaintext is encrypted in raw form.
        :return: Non-randomized RandomizableCiphertext object containing the encrypted value of the
            plaintext.
        """
        if isinstance(plaintext, EncodedPlaintext):
            return self._unsafe_encrypt_raw(plaintext)
        if apply_encoding:
            return self._unsafe_encrypt_raw(self.encode(plaintext))
        return self._unsafe_encrypt_raw(EncodedPlaintext(cast(RP, plaintext), self))

    @abstractmethod
    def _unsafe_encrypt_raw(self, plaintext: EncodedPlaintext[RP]) -> RC:
        """
        Encrypts an encoded (raw) plaintext value, but does not apply randomness.

        :param plaintext: EncodedPlaintext object containing the raw value to be encrypted.
        :return: Non-randomized RandomizableCiphertext object containing the encrypted plaintext.
        """

    def shut_down(self) -> None:
        """
        Give the shut down signal to the scheme's randomness.
        This tells the threads to gracefully shut down.
        """
        self.randomness.shut_down()

    def boot_generation(
        self,
        nr_of_threads: Optional[int] = None,
        path: Optional[str] = None,
        start_generation: bool = True,
    ) -> None:
        """
        calls the boot_generation method of the internal randomness

        :param nr_of_threads: number of generation threads.
            (Default: None, the nr_of_threads parameter is taken from the original __init__)
        :param path: path to the file containing randomizations.
            (Default: None, the path parameter is taken from the original __init__)
        :param start_generation: flag that determines whether the threads start generating
            immediately.
        """
        self.randomness.boot_generation(nr_of_threads, path, start_generation)

    def __del__(self) -> None:
        self.randomness.shut_down()
