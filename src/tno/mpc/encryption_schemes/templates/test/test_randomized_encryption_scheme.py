"""
File containing all tests regarding the RandomizedEncryptionScheme functionalities.
"""
# pylint: disable=missing-function-docstring,protected-access

from __future__ import annotations

from random import randint
from typing import Any, Tuple

import pytest

from tno.mpc.encryption_schemes.templates.asymmetric_encryption_scheme import (
    AsymmetricEncryptionScheme,
    SecretKey,
)
from tno.mpc.encryption_schemes.templates.encryption_scheme import (
    EncodedPlaintext,
    EncryptionSchemeWarning,
)
from tno.mpc.encryption_schemes.templates.random_sources import (
    ContextlessSource,
    ProcessSource,
)
from tno.mpc.encryption_schemes.templates.randomized_encryption_scheme import (
    WARN_INEFFICIENT_RANDOMIZATION,
    RandomizableCiphertext,
    RandomizedEncryptionScheme,
)


class DummyPublicKey:
    """
    Dummy public key for tests.
    """

    class SerializedDummyPublicKey:  # pylint: disable=too-few-public-methods
        """
        Dummy SerializedPublicKey for tests.
        """

    def serialize(self, **_kwargs: Any) -> SerializedDummyPublicKey:
        r"""
        Dummy serializer.

        :param \**_kwargs: Ignored keyword parameters.
        :return: Serialized public key.
        """
        return DummyPublicKey.SerializedDummyPublicKey()

    @staticmethod
    def deserialize(
        obj: DummyPublicKey.SerializedDummyPublicKey, **_kwargs: Any
    ) -> DummyPublicKey:
        r"""
        Dummy deserializer.

        :param obj: object to be deserialized.
        :param \**_kwargs: Ignored keyword parameters.
        :return: Deserialized public key.
        """
        del obj
        return DummyPublicKey()


class DummyRandomizableCiphertext(
    RandomizableCiphertext[Tuple[DummyPublicKey, SecretKey], int, int, int, int]
):
    """
    Dummy RandomizableCiphertext for tests.
    """

    def apply_randomness(self, randomization_value: Any) -> None:
        """
        Presumably applies randomness.

        :param randomization_value: Ignored value.
        """
        del randomization_value


class DummyEncryptionScheme(
    RandomizedEncryptionScheme[
        Tuple[DummyPublicKey, SecretKey],
        Any,
        Any,
        Any,
        DummyRandomizableCiphertext,
        int,
    ],
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
        """
        return EncodedPlaintext(plaintext, self)

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
        ciphertext_2: Any | Any,
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
        ciphertext_2: Any | Any,
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
    def generate_key_material(
        *args: Any, **kwargs: Any
    ) -> tuple[DummyPublicKey, SecretKey]:
        r"""
        Static method to generate key material.

        :param \*args: arguments used to generate key material
        :param \**kwargs: keyword arguments used to generate key material
        :return: a tuple consisting of a public key and a secret (private) key
        :raise NotImplementedError: is raised when not implemented
        """
        raise NotImplementedError()

    def _unsafe_encrypt_raw(
        self, plaintext: EncodedPlaintext[Any]
    ) -> DummyRandomizableCiphertext:
        """
        Method to encrypt an encoded plaintext value to a ciphertext without randomization.

        :param plaintext: an encoded plaintext to encrypt
        :return: a ciphertext
        """
        return DummyRandomizableCiphertext(plaintext, self)

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
        cls: type[DummyEncryptionScheme], *args: Any, **kwargs: Any
    ) -> DummyEncryptionScheme:
        r"""
        Class method to generate a new EncryptionScheme from a security parameter.

        :param \*args: Security parameter(s) and optional extra arguments for the EncryptionScheme
            constructor.
        :param \**kwargs: Security parameter(s) and optional extra arguments for the
            EncryptionScheme constructor.
        :return: A new EncryptionScheme.
        :raise NotImplementedError: is raised when not implemented.
        """
        raise NotImplementedError()

    @classmethod
    def id_from_arguments(cls) -> int:
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
        AsymmetricEncryptionScheme.__init__(self, DummyPublicKey(), None)

    @staticmethod
    def _generate_randomness() -> int:
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


def test_if_fresh_ciphertext_is_randomized_then_raises_encryptionschemewarning() -> (
    None
):
    scheme = DummyEncryptionScheme()
    scheme.boot_randomness_generation(2)
    ciphertext = scheme.encrypt(1)
    with pytest.warns(EncryptionSchemeWarning, match=WARN_INEFFICIENT_RANDOMIZATION):
        ciphertext.randomize()


def test_when_no_source_defined_if_custom_randomness_source_added_then_yield_from_that_source() -> (
    None
):
    scheme = DummyEncryptionScheme()
    source = ContextlessSource([1, 2, 3])
    scheme.register_randomness_source(source)

    values = [scheme.get_randomness() for _ in range(3)]
    assert values == [1, 2, 3]


def test_when_process_source_defined_if_custom_randomness_source_added_then_yield_from_both_sources_in_order() -> (
    None
):
    scheme = DummyEncryptionScheme()
    source = ContextlessSource([1, 2, 3])
    scheme.boot_randomness_generation(7)
    scheme.register_randomness_source(source)

    values = [scheme.get_randomness() for _ in range(10)]
    assert len(values) == 10
    assert values[:3] == [1, 2, 3]


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_if_too_little_randomness_generation_then_raise_userwarning() -> None:
    """
    Test whether the bounded randomness generation sends a warning when surpassing bound.
    """
    scheme = DummyEncryptionScheme()
    scheme.get_randomness()
    with pytest.warns(UserWarning, match="on the fly"):
        scheme.shut_down()


def test_if_exactly_enough_randomness_generation_then_no_warning() -> None:
    scheme = DummyEncryptionScheme()
    scheme.boot_randomness_generation(1)
    scheme.get_randomness()


@pytest.mark.filterwarnings("ignore::UserWarning")
def test_if_too_much_randomness_generation_then_raise_userwarning() -> None:
    scheme = DummyEncryptionScheme()
    scheme.boot_randomness_generation(1)
    with pytest.warns(UserWarning, match="generation requests unused"):
        scheme.shut_down()


def test_if_call_boot_randomness_then_processes_are_activated_immediately() -> None:
    scheme = DummyEncryptionScheme()

    scheme.boot_randomness_generation(1)
    process_source = scheme._get_existing_process_source()
    assert process_source is not None
    scheme.get_randomness()

    assert scheme._randomness._is_active(process_source)


def test_if_boot_randomness_twice_then_adds_correctly() -> None:
    scheme = DummyEncryptionScheme()

    scheme.boot_randomness_generation(1)
    scheme.boot_randomness_generation(2)
    values = [scheme.get_randomness() for _ in range(3)]
    assert len(values) == 3


def test_if_shut_down_then_randomness_manager_is_also_shut_down(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheme = DummyEncryptionScheme()
    manager = scheme._randomness
    is_closed = False

    def closer() -> None:
        nonlocal is_closed
        is_closed = True

    monkeypatch.setattr(manager, "shutdown", closer)

    scheme.shut_down()
    assert is_closed
