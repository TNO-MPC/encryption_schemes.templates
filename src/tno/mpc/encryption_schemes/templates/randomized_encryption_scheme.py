"""
Generic classes for creating an EncryptionScheme that allows for precomputed, or stored randomness.
"""

from __future__ import annotations

import sys
import warnings
from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar, cast

from tno.mpc.encryption_schemes.templates._randomness_manager import (
    RR,
    RandomnessManager,
)
from tno.mpc.encryption_schemes.templates.random_sources import (
    ContextlessSource,
    ProcessSource,
)
from .encryption_scheme import (
    CV,
    KM,
    PT,
    RP,
    Ciphertext,
    EncodedPlaintext,
    EncryptionScheme,
    EncryptionSchemeWarning,
)

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

WARN_INEFFICIENT_RANDOMIZATION = (
    "Randomizing a fresh ciphertext. This indicates a potential inefficiency as the ciphertext is "
    "randomized while the current randomness in the ciphertext is still fresh. It is more "
    "efficient to skip this randomization."
)


class RandomizedEncryptionSchemeWarning(UserWarning):
    """
    Issued for warnings related to the randomness generation.
    """


class TooMuchRandomnessWarning(RandomizedEncryptionSchemeWarning):
    """
    Issued when more randomness has been generated than used by the protocol.
    """


class TooLittleRandomnessWarning(RandomizedEncryptionSchemeWarning):
    """
    Issued when less randomness has been generated than required by the
    protocol, resulting in randomness needing to be generated on the fly.
    """


class RandomizableCiphertext(
    Generic[KM, PT, RP, CV, RR], Ciphertext[KM, PT, RP, CV], ABC
):
    """
    Ciphertext that can be rerandomized. Subclass of Ciphertext.
    """

    scheme: RandomizedEncryptionScheme[KM, PT, RP, CV, Any, RR]

    def __init__(
        self,
        raw_value: Any,
        scheme: RandomizedEncryptionScheme[KM, PT, RP, CV, Self, RR],
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
            f"The raw value of {self.__class__.__name__} can be viewed through peek_value() or "
            "accessed via get_value(). The latter call also marks the ciphertext as not fresh."
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
    def fresh(self) -> bool:
        """
        Indicate whether the ciphertest has fresh randomness.

        Ciphertexts that are send to other parties should generally be fresh. This can be achieved
        by calling self.randomize().

        :return: True if the randomness is fresh, False otherwise.
        """
        return self._fresh

    def randomize(self) -> Self:
        """
        Rerandomize this ciphertext object.

        :return: The rerandomized object (self).
        """
        if self.fresh:
            warnings.warn(WARN_INEFFICIENT_RANDOMIZATION, EncryptionSchemeWarning)

        randomization_value = self.scheme.get_randomness()
        self.apply_randomness(randomization_value)
        self._fresh = True
        return self

    @abstractmethod
    def apply_randomness(self, randomization_value: RR) -> None:
        """
        Apply a random value to rerandomize this ciphertext.

        :param randomization_value: Random value used to rerandomize this ciphertext.
        """

    def __str__(self) -> str:
        """
        :return: String representation of RandomizedCiphertext.
        """
        return f"{self.__class__.__name__}<value={str(self.peek_value())}, fresh={self.fresh}>"


RC = TypeVar("RC", bound="RandomizableCiphertext[Any, Any, Any, Any, Any]")


class RandomizedEncryptionScheme(
    Generic[KM, PT, RP, CV, RC, RR], EncryptionScheme[KM, PT, RP, CV, RC], ABC
):
    """
    Abstract base class for a RandomizedEncryptionScheme. Subclass of EncryptionScheme
    """

    def __init__(
        self,
        debug: bool = False,
    ) -> None:
        """
        Initiate a RandomizedEncryptionScheme.

        :param debug: Flag to determine whether debug information should be displayed.
        """
        EncryptionScheme.__init__(self)
        self._randomness: RandomnessManager[RR] = RandomnessManager()
        self._randomness_source_on_request = ContextlessSource(
            iter(self._generate_randomness, None)
        )
        self._randomness.register_source(
            self._randomness_source_on_request,
            priority=0,
        )
        self._debug = debug

    def boot_randomness_generation(
        self,
        amount: int,
        max_workers: int | None = None,
    ) -> None:
        """
        Boots processes to generate randomness.

        Creates new randomness-generating processes if none exist yet. If they already exist,
        request them to generate more randomness.

        More specifically: if no ProcessSource is yet registered to the internal
        RandomnessManager, then such a source is registered with priority -10.

        NOTE: Please call shut_down after user the scheme to ensure that all sources are shut down
        properly!

        :param amount: Amount of random values to generate (additionally).
        :param max_workers: Number of workers that generate randomness in parallel. If None, then
            this will default to the number of CPUs on the current device. This parameter is
            ignored if there already are randomness-generating processes.
        """
        existing_process_source = self._get_existing_process_source()
        if existing_process_source:
            existing_process_source.increase_requested(amount)
        else:
            process_source = ProcessSource(
                self._generate_randomness,
                amount=amount,
                max_workers=max_workers,
                debug=self._debug,
            )
            self._randomness.register_source(process_source, priority=50, boot_now=True)

    def _get_existing_process_source(self) -> ProcessSource[RR] | None:
        """
        Get an existing process source.

        :return: A registered ProcessSource if it exists, None otherwise.
        """
        existing_process_sources = [
            source
            for source in self._randomness.sources
            if isinstance(source, ProcessSource)
        ]
        return existing_process_sources[0] if existing_process_sources else None

    def register_randomness_source(self, *args: Any, **kwargs: Any) -> None:
        """
        Register a new source of randomness.

        For the parameters, see :py:meth:`RandomnessManager.register_source`.
        """
        self._randomness.register_source(*args, **kwargs)

    def get_randomness(self) -> RR:
        """
        Get new randomness from the randomness source.

        :return: One random value.
        """
        return self._randomness.get_one()

    @staticmethod
    def _generate_randomness() -> RR:
        """
        Method to generate randomness for this particular scheme.

        :raise NotImplementedError: When scheme does not support randomness generation.
        :return: A single random element with respect to the scheme.
        """
        raise NotImplementedError()

    def _encrypt_raw(self, plaintext: EncodedPlaintext[RP]) -> RC:
        return self._unsafe_encrypt_raw(plaintext).randomize()

    def unsafe_encrypt(
        self, plaintext: PT | EncodedPlaintext[RP], apply_encoding: bool = True
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
        Shut down scheme's randomness manager and inform user of mismatch in amount of randomness
        requested and randomness used if applicable.

        Give the shut down signal to the scheme's randomness to shut down all managed sources.
        If the amount of randomness generated via boot_randomness_generation is not equal to the
        amount of randomness used by the scheme, a warning is issued to inform the user of the
        mismatch. This allows the user to tune the amount of pregenerated randomness and improve
        efficiency.
        """
        process_source = self._get_existing_process_source()
        if process_source is None:
            remaining_generation = 0
        else:
            remaining_generation = (
                process_source.nr_requested - process_source.nr_yielded
            )
        if remaining_generation > 0:
            warnings.warn(
                f"Requested more randomness to be generated than needed, "
                f"{remaining_generation} randomness generation requests unused.",
                TooMuchRandomnessWarning,
            )
        if self._randomness_source_on_request.nr_yielded > 0:
            warnings.warn(
                f"Generated {self._randomness_source_on_request.nr_yielded} randomness on the fly.",
                TooLittleRandomnessWarning,
            )
        self._randomness.shutdown()

    def __del__(self) -> None:
        """
        Delete the object gracefully.
        """
        self.shut_down()
