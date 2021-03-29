"""
Generic classes for creating an EncryptionScheme that allows for precomputed, or stored randomness.
"""

from abc import ABC, abstractmethod
from threading import Event, Lock, Thread
from typing import Any, Callable, cast, List, Optional, TypeVar
from queue import Empty, Full, Queue

from .encryption_scheme import (
    CT,
    CV,
    Ciphertext,
    EncryptionScheme,
    KM,
    PT,
    RP,
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
        nr_of_threads: int = 1,
        path: Optional[str] = None,
        separator: str = ",",
        start_generation: bool = True,
        debug: bool = False,
    ):
        """
        Construct a Randomness object. This construction starts generation workers and a file worker
        that generate new randomness using the given generation function and abstract random from a
        file respectively. This happens in separate threads and the random elements are placed in a
        (thread-safe) queue. This queue can then be used to request random elements at encryption
        time.

        :param debug: flag to determine whether debug information should be displayed
            (Default: False)
        :param start_generation: flag to determine whether all threads should immediately start
            generating randomness (Default: True)
        :param max_size: maximum size of the buffer of randomizations. (Default: 100)
        :param nr_of_threads: number of threads that generate randomizations in parallel.
        :param generation_function: Function that generates one random value.
        :param randomizations: Precomputed in-memory randomness to be stored in this object for
            usage in an encryption scheme. (Default: None)
        :param path: Optional path to a file containing randomness. (Default: None)
        :param separator: Separator between random numbers in the file. (Default: ",")
        """
        if randomizations is None:
            randomizations = Queue(max_size)
        self.generation_function = generation_function
        self.nr_of_threads = nr_of_threads
        self.randomizations = randomizations
        self.has_buffer = self.randomizations.qsize() > 0
        self.path = path
        self.file_position = 0
        self.delimiter = separator
        self.debug = debug

        self.print_lock = Lock()

        self._generating = Event()
        self._shutdown = Event()

        self.has_file = path is not None
        # variable that saves part of the file containing randomizations
        self._chunk = ""

        self.generation_threads: List[Thread] = []
        self.file_thread: Optional[Thread] = None

        # variable that saves the position in the file we were reading
        self._file_position = 0

        # set up threads that generate randomizations and place them in the appropriate queue
        self.boot_generation(nr_of_threads, path, start_generation)

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
        shut down the generation threads and file thread if they are still running.
        Then, initialise new generation threads and a file thread.

        :param nr_of_threads: number of generation threads.
            (Default: None, the nr_of_threads parameter is taken from the original __init__)
        :param path: path to the file containing randomizations.
            (Default: None, the path parameter is taken from the original __init__)
        :param start_generation: flag that determines whether the threads start generating
            immediately (Default: True).
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

    def get_one(self) -> Any:
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
    ):
        """
        Construct a RandomizableCiphertext, with the given value for the given EncryptionScheme.

        :param raw_value: Ciphertext value.
        :param scheme: RandomizedEncryptionScheme that is used to encrypt this ciphertext.
        :raise TypeError: When scheme has the incorrect type.
        """
        if not isinstance(scheme, RandomizedEncryptionScheme):
            raise TypeError(f"expected RandomizedEncryptionScheme, got {type(scheme)}")
        super().__init__(raw_value, scheme)

    def randomize(self: RC) -> None:
        """
        Rerandomize this ciphertext object.
        """
        randomization_value = cast(
            RandomizedEncryptionScheme[KM, PT, RP, CV, RC], self.scheme
        ).get_randomness()
        self.apply_randomness(randomization_value)

    @abstractmethod
    def apply_randomness(self, randomization_value: Any) -> None:
        """
        Apply a random value to rerandomize this ciphertext.

        :param randomization_value: Random value used to rerandomize this ciphertext.
        :raise NotImplementedError: When scheme does not support rerandomization.
        """
        raise NotImplementedError()


class RandomizedEncryptionScheme(EncryptionScheme[KM, PT, RP, CV, CT], ABC):
    """
    Abstract base class for a RandomizedEncryptionScheme. Subclass of EncryptionScheme
    """

    def __init__(
        self,
        randomizations: Optional["Queue[int]"] = None,
        max_size: int = 100,
        nr_of_threads: int = 1,
        path: Optional[str] = None,
        separator: str = ",",
        start_generation: bool = True,
        debug: bool = False,
    ):
        """
        Initiate a Randomness variable with the given parameters to be used for
        randomizing ciphertexts.

        :param debug: flag to determine whether debug information should be displayed
            (Default: False)
        :param start_generation: flag that determines whether the scheme starts generating
            randomness immediately (Default: True)
        :param randomizations: queue with randomizations. If no queue is given, it creates a
            fresh one (Default: None)
        :param max_size: maximum size of the queue (Default: 100)
        :param nr_of_threads: number of generation worker threads that should be started
            (Default: 1)
        :param path: path (including filename) to the file that contains randomizations.
            By default no path is given and no randomness is extracted from any files. (Default: "")
        :param separator: separator for the random values in the given file (Default: ",")
        """
        self.randomness = Randomness(
            self.generate_randomness,
            randomizations=randomizations,
            max_size=max_size,
            nr_of_threads=nr_of_threads,
            path=path,
            separator=separator,
            start_generation=start_generation,
            debug=debug,
        )
        EncryptionScheme.__init__(self)

    def get_randomness(self) -> Any:
        """
        Get new randomness from the randomness source.

        :return: One random value.
        """
        return self.randomness.get_one()

    @abstractmethod
    def generate_randomness(self) -> Any:
        """
        Method to generate randomness for this particular scheme.

        :raise NotImplementedError: When scheme does not support randomness generation.
        :return: A list containing number_of_randomizations random numbers.
        """
        raise NotImplementedError()

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
            immediately (Default: True).
        """
        self.randomness.boot_generation(nr_of_threads, path, start_generation)

    def __del__(self) -> None:
        self.randomness.shut_down()
