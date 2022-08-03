"""
File containing all tests regarding the RandomizedEncryptionScheme functionalities.
"""

from __future__ import annotations

import time
from pathlib import Path
from random import randint
from threading import Event, Thread
from typing import Any, Tuple, Type, Union

import pytest

from tno.mpc.encryption_schemes.templates.asymmetric_encryption_scheme import (
    AsymmetricEncryptionScheme,
    PublicKey,
    SecretKey,
)
from tno.mpc.encryption_schemes.templates.encryption_scheme import EncodedPlaintext
from tno.mpc.encryption_schemes.templates.randomized_encryption_scheme import (
    RandomizedEncryptionScheme,
)


class DummyEncryptionScheme(
    RandomizedEncryptionScheme[Tuple[PublicKey, SecretKey], Any, Any, Any, Any],
    AsymmetricEncryptionScheme[Any, Any, Any, Any, Any, Any, Any],
):
    """
    Subclass of RandomizedEncryptionScheme for testing the randomness generation functionality.
    Additionally a subclass of AsymmetricEncryptionScheme to test compatibility
    No encoding, decoding, encryption or decryption functionality is available; only a
    hide_value function takes some randomness and applies a xor to the random value and a
    given value.
    """

    # region mandatory functions
    def encode(self, plaintext: Any) -> EncodedPlaintext[Any]:
        """
        Method to encode a plaintext value.

        :param plaintext: a plaintext value
        :return: an encoded plaintext
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def decode(self, encoded_plaintext: EncodedPlaintext[Any]) -> Any:
        """
        Method to decode an encoded plaintext value.

        :param encoded_plaintext: an encoded plaintext value
        :return: a plaintext
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def neg(self, ciphertext: Any) -> Any:
        """
        Method to negate a ciphertext value.

        :param ciphertext: a ciphertext value
        :return: a negated ciphertext
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def add(
        self,
        ciphertext_1: Any,
        ciphertext_2: Union[Any, Any],
    ) -> Any:
        """
        Method to sum two ciphertext values or a ciphertext with a plaintext.

        :param ciphertext_1: a ciphertext value
        :param ciphertext_2: a ciphertext, or plaintext, value
        :return: a summed ciphertext
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def mul(
        self,
        ciphertext_1: Any,
        ciphertext_2: Union[Any, Any],
    ) -> Any:
        """
        Method to multiply two ciphertext values or a ciphertext with a plaintext.

        :param ciphertext_1: a ciphertext value
        :param ciphertext_2: a ciphertext, or plaintext, value
        :return: a ciphertext (the product)
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def pow(self, ciphertext: Any, power: int) -> Any:
        """
        Method to raise a ciphertext value to the power of an integer value.

        :param ciphertext: a ciphertext value
        :param power: an integer power value
        :return: a ciphertext (the exponent)
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    @staticmethod
    def generate_key_material(*args: Any, **kwargs: Any) -> Tuple[PublicKey, SecretKey]:
        r"""
        Static method to generate key material.

        :param \*args: arguments used to generate key material
        :param \**kwargs: keyword arguments used to generate key material
        :return: a tuple consisting of a public key and a secret (private) key
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def _unsafe_encrypt_raw(self, plaintext: EncodedPlaintext[Any]) -> Any:
        """
        Method to encrypt an encoded plaintext value to a ciphertext without randomization.

        :param plaintext: an encoded plaintext to encrypt
        :return: a ciphertext
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def _decrypt_raw(self, ciphertext: Any) -> EncodedPlaintext[Any]:
        """
        Method to decrypt a ciphertext to its encoded plaintext value.

        :param ciphertext: a ciphertext to decrypt
        :return: an encoded plaintext value
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def __eq__(self, other: Any) -> bool:
        """
        Method to compare this object to another object. Returns True if they are equal.

        :param other: another object
        :return: True if the objects are equal
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    @classmethod
    def from_security_parameter(
        cls: Type[DummyEncryptionScheme], *args: Any, **kwargs: Any
    ) -> DummyEncryptionScheme:
        r"""
        Class method to generate a new EncryptionScheme from a security parameter.

        :param \*args: Security parameter(s) and optional extra arguments for the EncryptionScheme
            constructor
        :param \**kwargs: Security parameter(s) and optional extra arguments for the EncryptionScheme
            constructor
        :return: A new EncryptionScheme
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    @classmethod
    def id_from_arguments(cls) -> int:  # type: ignore[override]
        """
        Get the fixed ID (42) of this dummy EncryptionScheme.

        :return: 42
        """
        return 42

    # endregion

    def __init__(self, **kwargs: Any) -> None:
        r"""
        Create RandomizedEncryptionScheme with the given randomness source and optional arguments.
        :param randomness: Randomness object, that is used to generate all randomness for
            this scheme.

        :param \**kwargs: Optional extra arguments for this EncryptionScheme.
        """
        RandomizedEncryptionScheme.__init__(self, **kwargs)
        AsymmetricEncryptionScheme.__init__(self, PublicKey(), None)

    def generate_randomness(self) -> int:  # pylint: disable=no-self-use
        """
        Method to generate randomness for this particular scheme.

        :return: A list containing number_of_randomizations random numbers.
        """
        return randint(1, 100)

    def hide_value(self, value: int) -> int:
        """
        Method to hide a value using randomness, by xor-ing the value with randomness.

        :param value: the value to be hidden
        :return: hidden value
        """

        rand = self.get_randomness()
        return value ^ rand


prefix = Path(__file__).parents[0]
path_small = f"{prefix}/random_numbers_small.txt"
path_large = f"{prefix}/random_numbers_large.txt"
BOOT_AND_GET_SLEEP_TIME = 0.5


def shut_down(scheme: DummyEncryptionScheme, signal: Event) -> None:
    """
    Calls shutdown on scheme and sets a signal.

    :param scheme: the scheme to shutdown
    :param signal: the signal to set
    """
    scheme.shut_down()
    signal.set()


def get_one(scheme: DummyEncryptionScheme, signal: Event) -> None:
    """
    Gets one random element from scheme and and sets a signal.

    :param scheme: the scheme to retrieve a random element from
    :param signal: the signal to set
    """
    _ = scheme.randomness.get_one()
    signal.set()


def test_external_shutdown() -> None:
    """
    Test whether the program hangs due to threading or not.
    """
    nr_of_threads = 10
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, start_generation=True, debug=False
    )
    assert len(scheme.randomness.generation_threads) == nr_of_threads
    for thread in scheme.randomness.generation_threads:
        assert thread.is_alive()
    time.sleep(1)


def test_boot_generation() -> None:
    """
    Test whether we can properly stop and start new generation threads.
    """
    nr_of_threads = 3
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads,
        start_generation=False,
        debug=True,
    )
    assert len(scheme.randomness.generation_threads) == nr_of_threads
    assert scheme.randomness.path is None
    time.sleep(1)
    new_nr_of_threads = 10
    scheme.randomness.boot_generation(
        nr_of_threads=new_nr_of_threads, path=path_small, start_generation=False
    )
    time.sleep(0.6)
    assert len(scheme.randomness.generation_threads) == new_nr_of_threads
    assert scheme.randomness.path == path_small
    assert len(scheme.randomness) == 0
    scheme.randomness.start_generating()

    time.sleep(0.2)
    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    shut_down_thread = Thread(target=shut_down, daemon=True, args=(scheme, signal))
    shut_down_thread.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(BOOT_AND_GET_SLEEP_TIME)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_shutdown_no_threads() -> None:
    """
    Test whether we can properly call the shut down for generation threads when none exist.
    """
    nr_of_threads = 0
    scheme = DummyEncryptionScheme(nr_of_threads=nr_of_threads, start_generation=True)
    scheme.randomness.debug = True
    assert len(scheme.randomness.generation_threads) == nr_of_threads
    time.sleep(2)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    shut_down_thread = Thread(target=shut_down, daemon=True, args=(scheme, signal))
    shut_down_thread.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(BOOT_AND_GET_SLEEP_TIME)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_shutdown_no_generation() -> None:
    """
    Test whether we can properly shut down threads that are currently not generating.
    """
    nr_of_threads = 3
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_small, start_generation=False
    )
    time.sleep(0.5)

    # the workers should be waiting for the generation signal
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    shut_down_thread = Thread(target=shut_down, daemon=True, args=(scheme, signal))
    shut_down_thread.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(BOOT_AND_GET_SLEEP_TIME)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_shutdown_generation_small() -> None:
    """
    Test whether we can properly shut down a generating threads that obtain randomness from a
    small file.
    """
    nr_of_threads = 1
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_small, start_generation=True
    )
    scheme.randomness.debug = True
    time.sleep(2)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    shut_down_thread = Thread(target=shut_down, daemon=True, args=(scheme, signal))
    shut_down_thread.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(BOOT_AND_GET_SLEEP_TIME)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_shutdown_generation_large() -> None:
    """
    Test whether we can properly shut down a generating threads that obtain randomness from a
    large file.
    """
    nr_of_threads = 1
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_large, start_generation=True
    )
    scheme.randomness.debug = True
    time.sleep(0.1)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    shut_down_thread = Thread(target=shut_down, daemon=True, args=(scheme, signal))
    shut_down_thread.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(BOOT_AND_GET_SLEEP_TIME)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_get_one_no_threads() -> None:
    """
    Test whether the get one random element call is not blocking when no randomness threads are
    used.
    """
    nr_of_threads = 0
    scheme = DummyEncryptionScheme(nr_of_threads=nr_of_threads, start_generation=True)
    scheme.randomness.debug = True
    time.sleep(0.1)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    get_one_thread = Thread(target=get_one, daemon=True, args=(scheme, signal))
    get_one_thread.start()

    # get_one should happen quickly
    time.sleep(BOOT_AND_GET_SLEEP_TIME)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set(), "the get_one call is blocking"


def test_get_one_with_threads_no_generation() -> None:
    """
    Test whether the get one random element call is not blocking when no randomness is generated,
    but threads do exist.
    """
    nr_of_threads = 5
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_large, start_generation=False
    )
    scheme.randomness.debug = True
    time.sleep(0.1)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    get_one_thread = Thread(target=get_one, daemon=True, args=(scheme, signal))
    get_one_thread.start()

    # get_one should happen quickly
    time.sleep(BOOT_AND_GET_SLEEP_TIME)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set(), "the get_one call is blocking"
    scheme.shut_down()


def test_get_one_with_threads_with_generation() -> None:
    """
    Test whether the get one random element call is not blocking, when randomness is being
    generated, by a couple of threads and from a large file.
    """
    nr_of_threads = 5
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_large, start_generation=True
    )
    scheme.randomness.debug = True
    time.sleep(0.1)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    get_one_thread = Thread(target=get_one, daemon=True, args=(scheme, signal))
    get_one_thread.start()

    # get_one should happen quickly
    time.sleep(BOOT_AND_GET_SLEEP_TIME)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set(), "the get_one call is blocking"
    scheme.shut_down()


def test_bounded_generation() -> None:
    """
    Test whether the randomness generation is stopped when a bound is given.
    """
    with pytest.warns(None) as warnings:  # type: ignore
        nr_of_threads = 5
        generation_bound = 10
        scheme = DummyEncryptionScheme(
            nr_of_threads=nr_of_threads, total=generation_bound, start_generation=False
        )
        scheme.randomness.debug = True
        time.sleep(0.1)

        scheme.randomness.start_generating()
        time.sleep(BOOT_AND_GET_SLEEP_TIME)
        scheme.randomness.safe_print("checking assert")
        assert (
            not scheme.randomness._generating.is_set()  # pylint: disable=protected-access
        ), "The scheme is still set to generate."
        assert (
            scheme.randomness.total == generation_bound
        ), f"Bound is {scheme.randomness.total}, expected {generation_bound}."
    assert not warnings, f"Warnings received {[str(_) for _ in warnings]}."
    scheme.shut_down()


def test_bounded_generation_warning() -> None:
    """
    Test whether the bounded randomness generation sends a warning when surpassing bound.
    """
    with pytest.warns(UserWarning) as _:
        nr_of_threads = 5
        generation_bound = 100
        scheme = DummyEncryptionScheme(
            nr_of_threads=nr_of_threads, total=generation_bound, start_generation=False
        )
        scheme.randomness.debug = True
        time.sleep(0.1)

        scheme.randomness.start_generating()
        overflow = generation_bound + nr_of_threads + 1
        for _ in range(overflow):
            scheme.randomness.get_one()
    scheme.shut_down()


def test_generation_worker() -> None:
    """
    Test whether a scheme with only one generating thread generates and returns randomness
    correctly.
    """
    scheme = DummyEncryptionScheme(nr_of_threads=1)
    len_check_1 = len(scheme.randomness)
    time.sleep(2)
    len_check_2 = len(scheme.randomness)
    scheme.randomness.stop_generating()
    time.sleep(2)
    len_check_3 = len(scheme.randomness)
    time.sleep(1)
    len_check_4 = len(scheme.randomness)
    assert len_check_2 > 0, "generation worker did not generate anything"
    assert (
        len_check_1 <= len_check_2 <= len_check_3
    ), "somehow we lost some queue entries"
    assert (
        len_check_3 == len_check_4
    ), "workers did not stop generating after stop sign was given"
    _ = scheme.hide_value(1)
    # the generation worker could have been still buffering, so the length can be either
    # len_check_4 or len_check_4 - 1
    # to confirm, hide another value. The buffer length should then be decreased by 1
    len_check_5 = len(scheme.randomness)
    _ = scheme.hide_value(0)
    len_check_6 = len(scheme.randomness)
    scheme.shut_down()
    assert (
        len_check_6 == len_check_5 - 1
    ), "queue size did not change after hiding operation"


def test_file_worker() -> None:
    """
    Test whether a scheme with only one file worker generates and returns randomness correctly.
    """
    scheme = DummyEncryptionScheme(nr_of_threads=0, path=path_small)
    len_check_1 = len(scheme.randomness)
    time.sleep(2)
    len_check_2 = len(scheme.randomness)
    scheme.randomness.stop_generating()
    time.sleep(2)
    len_check_3 = len(scheme.randomness)
    time.sleep(1)
    len_check_4 = len(scheme.randomness)
    assert len_check_2 > 0, "file worker did not generate anything"
    assert (
        len_check_1 <= len_check_2 <= len_check_3
    ), "somehow we lost some queue entries"
    assert (
        len_check_3 == len_check_4
    ), "workers did not stop generating after stop sign was given"
    _ = scheme.hide_value(1)
    # the file worker could be waiting until a spot in the queue is freed up
    # (this happens when the buffer is full), so the length can be either
    # len_check_4 or len_check_4 - 1
    # to confirm, hide another value. The buffer length should then be decreased by 1
    len_check_5 = len(scheme.randomness)
    _ = scheme.hide_value(0)
    len_check_6 = len(scheme.randomness)
    scheme.shut_down()
    assert (
        len_check_6 == len_check_5 - 1
    ), "queue size did not change after hiding operation"


def test_combined_workers() -> None:
    """
    Test whether a scheme with multiple generating threads and a file thread generates and
    returns randomness properly.
    """
    nr_of_threads = 10
    scheme = DummyEncryptionScheme(nr_of_threads=nr_of_threads, path=path_small)
    len_check_1 = len(scheme.randomness)
    time.sleep(2)
    len_check_2 = len(scheme.randomness)
    scheme.randomness.stop_generating()
    time.sleep(2)
    len_check_3 = len(scheme.randomness)
    time.sleep(1)
    len_check_4 = len(scheme.randomness)
    assert len_check_2 > 0, "workers did not generate anything"
    assert (
        len_check_1 <= len_check_2 <= len_check_3
    ), "somehow we lost some queue entries"
    assert (
        len_check_3 == len_check_4
    ), "workers did not stop generating after stop sign was given"
    # the workers could be waiting until a spot in the queue is freed up
    # (this happens when the buffer is full), so the length
    # can stay the same over the next <nr_of_threads> + 1 hiding operations
    # to confirm, hide as many values as there are workers.
    # The hiding operations afterwards should then decrease the buffer length by 1
    for _ in range(nr_of_threads + 1):
        __ = scheme.hide_value(1)
    len_check_5 = len(scheme.randomness)
    _ = scheme.hide_value(0)
    len_check_6 = len(scheme.randomness)
    scheme.shut_down()
    assert (
        len_check_6 == len_check_5 - 1
    ), "queue size did not change after hiding operation"


def test_resume_generation() -> None:
    """
    Tests whether stopping and resuming randomness generation works as intended.
    """
    nr_of_threads = 10
    scheme = DummyEncryptionScheme(nr_of_threads=nr_of_threads, path=path_small)
    time.sleep(2)
    scheme.randomness.stop_generating()
    time.sleep(2)
    len_check_3 = len(scheme.randomness)
    time.sleep(1)
    len_check_4 = len(scheme.randomness)
    assert (
        len_check_3 == len_check_4
    ), "workers did not stop generating after stop sign was given"
    # the workers could be waiting until a spot in the queue is freed up
    # (this happens when the buffer is full), so the length
    # can stay the same over the next <nr_of_threads> + 1 hiding operations
    # to confirm, hide as many values as there are workers.
    # The hiding operations afterwards should then decrease the buffer length by 1
    for _ in range(nr_of_threads + 1):
        __ = scheme.hide_value(1)
    len_check_5 = len(scheme.randomness)
    for _ in range(10):
        __ = scheme.hide_value(0)
    len_check_6 = len(scheme.randomness)
    assert (
        len_check_6 == len_check_5 - 10
    ), "queue size did not change after hiding operation"
    scheme.randomness.start_generating()
    time.sleep(3)
    len_check_7 = len(scheme.randomness)
    scheme.shut_down()
    assert len_check_7 > len_check_6, "generation did not resume"


def test_adding_worker() -> None:
    """
    Tests whether adding a worker to an encryption scheme works as intended.
    """
    nr_of_threads = 10
    scheme = DummyEncryptionScheme(nr_of_threads=nr_of_threads, path=path_small)
    time.sleep(0.2)
    assert len(scheme.randomness.generation_threads) == nr_of_threads
    scheme.randomness.add_generation_worker()
    assert len(scheme.randomness.generation_threads) == nr_of_threads + 1
    for thread in scheme.randomness.generation_threads:
        assert thread.is_alive()

    scheme.shut_down()
