import time
from pathlib import Path
from random import randint
from typing import Tuple, Union
from threading import Event, Thread

from tno.mpc.encryption_schemes.templates.asymmetric_encryption_scheme import (
    AsymmetricEncryptionScheme,
    PK,
    SK,
)
from tno.mpc.encryption_schemes.templates.encryption_scheme import (
    Ciphertext,
    EncodedPlaintext,
    EncryptionScheme,
    PT,
    CV,
    KM,
    RP,
    CT,
)
from tno.mpc.encryption_schemes.templates.randomized_encryption_scheme import (
    RandomizedEncryptionScheme,
)


class DummyEncryptionScheme(
    RandomizedEncryptionScheme[KM, PT, RP, CV, CT],
    AsymmetricEncryptionScheme[KM, PT, RP, CV, CT, PK, SK],
):
    """
    Subclass of RandomizedEncryptionScheme for testing the randomness generation functionality.
    Additionally a subclass of AsymmetricEncryptionScheme to test compatibility
    No encoding, decoding, encryption or decryption functionality is available; only a
    hide_value function takes some randomness and applies a xor to the random value and a
    given value.
    """

    # region mandatory functions
    def encode(self, plaintext: PT) -> EncodedPlaintext:
        raise NotImplementedError()

    def decode(self, encoded_plaintext: EncodedPlaintext) -> PT:
        raise NotImplementedError()

    def neg(self, ciphertext: Ciphertext):
        raise NotImplementedError()

    def add(
        self,
        ciphertext_1: Ciphertext,
        ciphertext_2: Union[Ciphertext, PT],
    ):
        raise NotImplementedError()

    def mul(
        self,
        ciphertext_1: Ciphertext,
        ciphertext_2: Union[Ciphertext, PT],
    ):
        raise NotImplementedError()

    def pow(self, ciphertext: Ciphertext, power: int):
        raise NotImplementedError()

    @staticmethod
    def generate_key_material(*args, **kwargs) -> Tuple[PK, SK]:
        raise NotImplementedError()

    def _encrypt_raw(self, plaintext: EncodedPlaintext) -> Ciphertext:
        raise NotImplementedError()

    def _decrypt_raw(self, ciphertext: Ciphertext) -> EncodedPlaintext:
        raise NotImplementedError()

    def __eq__(self, other):
        raise NotImplementedError()

    @classmethod
    def from_security_parameter(cls, *args, **kwargs) -> "EncryptionScheme":
        pass

    # endregion

    def __init__(self, **kwargs):
        """
        Create RandomizedEncryptionScheme with the given randomness source and optional arguments.
        :param randomness: Randomness object, that is used to generate all randomness for
            this scheme.
        :param kwargs: Optional extra arguments for this EncryptionScheme.
        """
        RandomizedEncryptionScheme.__init__(self, **kwargs)
        AsymmetricEncryptionScheme.__init__(self, None, None)

    def generate_randomness(self) -> int:
        """
        Method to generate randomness for this particular scheme.
        :return: A list containing number_of_randomizations random numbers.
        """
        return randint(1, 100)

    def hide_value(self, value: int):
        rand = self.get_randomness()
        return value ^ rand


prefix = Path(__file__).parents[0]
path_small = f"{prefix}/random_numbers_small.txt"
path_large = f"{prefix}/random_numbers_large.txt"


# This is a manual test to determine whether the program hangs due to threading
def test_external_shutdown():
    nr_of_threads = 10
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, start_generation=True, debug=False
    )
    assert len(scheme.randomness.generation_threads) == nr_of_threads
    for thread in scheme.randomness.generation_threads:
        assert thread.is_alive()
    time.sleep(1)


def test_boot_generation():
    nr_of_threads = 3
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, start_generation=False, debug=True
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

    def shut_down():
        scheme.shut_down()
        signal.set()

    t = Thread(target=shut_down, daemon=True)
    t.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(0.5)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_shutdown_no_threads():
    nr_of_threads = 0
    scheme = DummyEncryptionScheme(nr_of_threads=nr_of_threads, start_generation=True)
    scheme.randomness.debug = True
    assert len(scheme.randomness.generation_threads) == nr_of_threads
    time.sleep(2)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    def shut_down():
        scheme.shut_down()
        signal.set()

    t = Thread(target=shut_down, daemon=True)
    t.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(0.5)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_shutdown_no_generation():
    nr_of_threads = 3
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_small, start_generation=False
    )
    time.sleep(0.5)

    # the workers should be waiting for the generation signal
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    def shut_down():
        scheme.shut_down()
        signal.set()

    t = Thread(target=shut_down, daemon=True)
    t.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(0.5)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_shutdown_generation_small():
    nr_of_threads = 1
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_small, start_generation=True
    )
    scheme.randomness.debug = True
    time.sleep(2)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    def shut_down():
        scheme.shut_down()
        signal.set()

    t = Thread(target=shut_down, daemon=True)
    t.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(0.5)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_shutdown_generation_large():
    nr_of_threads = 1
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_large, start_generation=True
    )
    scheme.randomness.debug = True
    time.sleep(0.1)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    def shut_down():
        scheme.shut_down()
        signal.set()

    t = Thread(target=shut_down, daemon=True)
    t.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(0.5)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set()


def test_get_one_no_threads():
    nr_of_threads = 0
    scheme = DummyEncryptionScheme(nr_of_threads=nr_of_threads, start_generation=True)
    scheme.randomness.debug = True
    time.sleep(0.1)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    def get_one():
        _ = scheme.randomness.get_one()
        signal.set()

    t = Thread(target=get_one, daemon=True)
    t.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(0.5)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set(), "the get_one call is blocking"


def test_get_one_with_threads_no_generation():
    nr_of_threads = 5
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_large, start_generation=False
    )
    scheme.randomness.debug = True
    time.sleep(0.1)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    def get_one():
        _ = scheme.randomness.get_one()
        signal.set()

    t = Thread(target=get_one, daemon=True)
    t.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(0.5)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set(), "the get_one call is blocking"
    scheme.shut_down()


def test_get_one_with_threads_with_generation():
    nr_of_threads = 5
    scheme = DummyEncryptionScheme(
        nr_of_threads=nr_of_threads, path=path_large, start_generation=True
    )
    scheme.randomness.debug = True
    time.sleep(0.1)

    # the workers should be waiting for a spot in the queue to open up
    # we now confirm whether the scheme is still able to shut down
    signal = Event()

    def get_one():
        _ = scheme.randomness.get_one()
        signal.set()

    t = Thread(target=get_one, daemon=True)
    t.start()

    # shutdown should happen within <Randomness.default_shutdown_timeout> seconds
    time.sleep(0.5)
    scheme.randomness.safe_print("checking assert")
    assert signal.is_set(), "the get_one call is blocking"
    scheme.shut_down()


def test_generation_worker():
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
    x = scheme.hide_value(1)
    # the generation worker could have been still buffering, so the length can be either
    # len_check_4 or len_check_4 - 1
    # to confirm, hide another value. The buffer length should then be decreased by 1
    len_check_5 = len(scheme.randomness)
    y = scheme.hide_value(0)
    len_check_6 = len(scheme.randomness)
    scheme.shut_down()
    assert (
        len_check_6 == len_check_5 - 1
    ), "queue size did not change after hiding operation"


def test_file_worker():
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
    x = scheme.hide_value(1)
    # the file worker could be waiting until a spot in the queue is freed up
    # (this happens when the buffer is full), so the length can be either
    # len_check_4 or len_check_4 - 1
    # to confirm, hide another value. The buffer length should then be decreased by 1
    len_check_5 = len(scheme.randomness)
    y = scheme.hide_value(0)
    len_check_6 = len(scheme.randomness)
    scheme.shut_down()
    assert (
        len_check_6 == len_check_5 - 1
    ), "queue size did not change after hiding operation"


def test_combined_workers():
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
    for i in range(nr_of_threads + 1):
        _ = scheme.hide_value(1)
    len_check_5 = len(scheme.randomness)
    _ = scheme.hide_value(0)
    len_check_6 = len(scheme.randomness)
    scheme.shut_down()
    assert (
        len_check_6 == len_check_5 - 1
    ), "queue size did not change after hiding operation"


def test_resume_generation():
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
    for i in range(nr_of_threads + 1):
        _ = scheme.hide_value(1)
    len_check_5 = len(scheme.randomness)
    for i in range(10):
        _ = scheme.hide_value(0)
    len_check_6 = len(scheme.randomness)
    assert (
        len_check_6 == len_check_5 - 10
    ), "queue size did not change after hiding operation"
    scheme.randomness.start_generating()
    time.sleep(3)
    len_check_7 = len(scheme.randomness)
    scheme.shut_down()
    assert len_check_7 > len_check_6, "generation did not resume"


def test_adding_worker():
    nr_of_threads = 10
    scheme = DummyEncryptionScheme(nr_of_threads=nr_of_threads, path=path_small)
    time.sleep(0.2)
    assert len(scheme.randomness.generation_threads) == nr_of_threads
    scheme.randomness.add_generation_worker()
    assert len(scheme.randomness.generation_threads) == nr_of_threads + 1
    for thread in scheme.randomness.generation_threads:
        assert thread.is_alive()

    scheme.shut_down()
