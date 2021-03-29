"""
Generic classes used for creating an encryption scheme.
"""

from abc import ABC, abstractmethod
from typing import (
    Any,
    cast,
    ClassVar,
    Dict,
    Generic,
    Type,
    TypeVar,
    Union,
)

from typing_extensions import Protocol, runtime_checkable

PT = TypeVar("PT")
RP = TypeVar("RP")
KM = TypeVar("KM")
CV = TypeVar("CV")
TCov = TypeVar("TCov", covariant=True)


@runtime_checkable
class SupportsNeg(Protocol[TCov]):
    """An ABC with one abstract method __neg__."""

    __slots__ = ()

    @abstractmethod
    def __neg__(self) -> TCov:
        pass


class EncodedPlaintext(Generic[RP]):
    """
    Class that contains the encoding of a plaintext for a particular scheme.
    """

    def __init__(self, value: RP, scheme: "EncryptionScheme[KM, PT, RP, CV, CT]"):
        """
        Constructs an EncodedPlaintext with the given value and encoding as specified in the scheme.

        :param value: value of the plaintext after encoding
        :param scheme: encryption scheme that specifies the used encoding
        :raise TypeError: When scheme has the incorrect type.
        """
        if not isinstance(scheme, EncryptionScheme):
            raise TypeError(
                f"Expected scheme to be an EncryptionScheme, not {type(scheme)}"
            )

        self.value = value
        self.scheme = scheme

    def __eq__(self, other: object) -> bool:
        """
        Compare equality of two ciphertexts.

        :param other: The other object to compare with.
        :raise TypeError: When other object has the incorrect type.
        :return: Boolean value representing (in)equality of self and other.
        """
        if not isinstance(other, EncodedPlaintext):
            raise TypeError(
                f"Expected comparison with an encoded plaintext, not {type(other)}"
            )
        return self.value == other.value and self.scheme == other.scheme


CT = TypeVar("CT", bound="Ciphertext[Any, Any, Any, Any]")


class Ciphertext(Generic[KM, PT, RP, CV]):
    """
    Object that contains the ciphertext value for a particular EncryptionScheme.
    Also includes functionality for arithmetic operations on ciphertexts.
    """

    def __init__(
        self: CT, raw_value: CV, scheme: "EncryptionScheme[KM, PT, RP, CV, CT]"
    ):
        """
        Constructs a Ciphertext with the given ciphertext value encrypted using the specified
        scheme.

        :param raw_value: value of the ciphertext
        :param scheme: encryption scheme used for creating this ciphertext
        """
        self._raw_value = raw_value
        self.scheme = scheme

    @property
    def value(self) -> CV:
        """
        Raw value of the ciphertext.

        :return: Value of the ciphertext
        """
        return self._raw_value

    def __neg__(self: CT) -> CT:
        """
        Negate the underlying plaintext of this ciphertext.

        :return: Negated ciphertext.
        """
        return self.scheme.neg(self)

    def __add__(self: CT, other: Union[CT, PT]) -> CT:
        """
        Add other to the underlying plaintext of this ciphertext.

        :param other: Plaintext value or other ciphertext. If Plaintext value we add the
            plaintext value to the underlying ciphertext. If ciphertext we add the both underlying
            ciphertexts.
        :return: Addition of other to this ciphertext.
        """
        return self.scheme.add(self, other)

    def __radd__(self: CT, other: Union[CT, PT]) -> CT:
        """
        Add other to the underlying plaintext of this ciphertext.

        :param other: Plaintext value or other ciphertext. If Plaintext value we add the
            plaintext value to the underlying ciphertext. If ciphertext we add the both underlying
            ciphertexts.
        :return: Addition of other to this ciphertext.
        """
        return self.scheme.add(self, other)

    def __sub__(self: CT, other: Union[CT, PT]) -> CT:
        """
        Subtract other from the underlying plaintext of this ciphertext.

        :param other: Plaintext value or other ciphertext. If Plaintext value we subtract the
            plaintext value from the underlying ciphertext. If ciphertext we subtract the both
            underlying ciphertexts.
        :raise TypeError: When the other object has an unsupported type for subtraction from this
            ciphertext.
        :return: Subtraction of other from this ciphertext.
        """
        if isinstance(other, SupportsNeg):
            return self.scheme.add(self, -other)
        # else
        raise TypeError(f"Unsupported operand type for -: {type(other)}")

    def __rsub__(self: CT, other: Union[CT, PT]) -> CT:
        """
        Subtract other from the underlying plaintext of this ciphertext.

        :param other: Plaintext value or other ciphertext. If Plaintext value we subtract the
            plaintext value from the underlying ciphertext. If ciphertext we subtract the both
            underlying ciphertexts.
        :return: Subtraction of other from this ciphertext.
        """
        return self.scheme.add(-self, other)

    def __mul__(self: CT, other: Union[CT, PT]) -> CT:
        """
        Multiply other with the underlying plaintext of this ciphertext.

        :param other: Plaintext value or other ciphertext. If Plaintext value we multiply the
            plaintext value with the underlying ciphertext. If ciphertext we multiply the both
            underlying ciphertexts.
        :return: Multiplication of other with this ciphertext.
        """
        return self.scheme.mul(self, other)

    def __rmul__(self: CT, other: Union[CT, PT]) -> CT:
        """
        Multiply other with the underlying plaintext of this ciphertext.

        :param other: Plaintext value or other ciphertext. If Plaintext value we multiply the
            plaintext value with the underlying ciphertext. If ciphertext we multiply the both
            underlying ciphertexts.
        :return: Multiplication of other with this ciphertext.
        """
        return self.scheme.mul(self, other)

    def __pow__(self: CT, power: int) -> CT:
        """
        Exponentiate underlying plaintext of this ciphertext with the given exponent.

        :param power: Exponent to which the underlying plaintext should be exponentiated.
        :return: Exponentiation of ciphertext to the given power.
        """
        return self.scheme.pow(self, power)


ES = TypeVar("ES", bound="EncryptionScheme[Any, Any, Any, Any, Any]")


class EncryptionScheme(ABC, Generic[KM, PT, RP, CV, CT]):
    """
    Abstract base class to define generic EncryptionScheme functionality. Can be used for all kinds
    of encryption scheme (e.g. Asymmetric, Symmetric).

    Most easily constructed using the from_security_parameter method.

    All abstract methods should be implemented by subclasses.
    """

    _instances: ClassVar[Dict[int, "EncryptionScheme[Any, Any, Any, Any, Any]"]] = {}

    @classmethod
    @abstractmethod
    def from_security_parameter(cls: Type[ES], *args: Any, **kwargs: Any) -> ES:
        """
        Generate a new EncryptionScheme from a security parameter.

        :param args: Security parameter(s) and optional extra arguments for the EncryptionScheme
            constructor.
        :param kwargs: Security parameter(s) and optional extra arguments for the EncryptionScheme
            constructor.
        :return: A new EncryptionScheme.
        """

    def __init__(self, *args: Any, **kwargs: Any):
        """
        Construct a new EncryptionScheme.
        """

    # region Quasi-singleton logic

    @classmethod
    def get_instance(cls: Type[ES], *args: Any, **kwargs: Any) -> ES:
        """
        Alternative to the constructor function to obtain a quasi-singleton object.
        This function can be called whenever a scheme needs to be initiated and ensures that
        identical calls will return a reference to the same object.

        :param args: regular arguments that would normally go into the constructor
        :param kwargs: regular keyword arguments that would normally go into the constructor
        :return: Either a newly instantiated scheme or a reference to an already existing scheme
        """
        identifier = cls.id_from_arguments(*args, **kwargs)
        if identifier in cls._instances:
            instance = cls._instances[identifier]
            # assert correct class, since _instances is shared among all EncryptionSchemes
            assert isinstance(instance, cls)
            return instance
        # else
        instance = cls(*args, **kwargs)
        cls._instances[identifier] = instance
        return instance

    @classmethod
    def id_from_arguments(cls, *args: Any, **kwargs: Any) -> int:
        """
        Method that turns the arguments for the constructor into an identifier. This identifier is
        used to find constructor calls that would result in identical schemes.

        :param args: regular arguments
        :param kwargs: regular keyword arguments
        :return: identifier of type int
        """
        return hash(
            tuple("from args") + tuple(args) + tuple(kwargs[i] for i in sorted(kwargs))
        )

    # endregion

    @staticmethod
    @abstractmethod
    def generate_key_material(*args: Any, **kwargs: Any) -> KM:
        """
        Method to generate key material (format depending on the type of scheme) for this scheme.

        :param args: Required arguments to generate said key material.
        :param kwargs: Required arguments to generate said key material.
        """

    @abstractmethod
    def encode(self, plaintext: PT) -> EncodedPlaintext[RP]:
        """
        Encode a supported Plaintext using the specified encoding scheme.

        :param plaintext: Plaintext to be encoded.
        :return: EncodedPlaintext object containing the encoded value.
        """

    @abstractmethod
    def decode(self, encoded_plaintext: EncodedPlaintext[RP]) -> PT:
        """
        Decode an EncodedPlaintext using the specified encoding scheme.

        :param encoded_plaintext: Plaintext to be decoded.
        :return: Decoded Plaintext value
        """

    def encrypt(
        self, plaintext: Union[PT, EncodedPlaintext[RP]], apply_encoding: bool = True
    ) -> CT:
        """
        Encrypts the entered (encoded) Plaintext. Also encodes the Plaintext when this is required.

        :param plaintext: Plaintext or EncodedPlaintext to be encrypted.
        :param apply_encoding: Boolean indicating whether a non-encoded plaintext should be encoded.
            If False, the plaintext is encrypted in raw form. Defaults to True.
        :return: Ciphertext object containing the encrypted value of the plaintext.
        """
        if not isinstance(plaintext, EncodedPlaintext):
            if apply_encoding:
                plaintext = self.encode(plaintext)
            else:
                plaintext = EncodedPlaintext(cast(RP, plaintext), self)
        return self._encrypt_raw(plaintext)

    def decrypt(self, ciphertext: CT, apply_encoding: bool = True) -> PT:
        """
        Decrypts the input ciphertext.

        :param ciphertext: Ciphertext to be decrypted.
        :param apply_encoding: Boolean indicating whether the decrypted ciphertext is decoded
            before it is returned. Defaults to True.
        :return: Plaintext decrypted value.
        """
        decrypted_ciphertext = self._decrypt_raw(ciphertext)
        return (
            self.decode(decrypted_ciphertext)
            if apply_encoding
            else cast(PT, decrypted_ciphertext.value)
        )

    @abstractmethod
    def _encrypt_raw(self, plaintext: EncodedPlaintext[RP]) -> CT:
        """
        Encrypts an encoded (raw) plaintext value.

        :param plaintext: EncodedPlaintext object containing the raw value to be encrypted.
        :return: Ciphertext object containing the encrypted plaintext.
        """

    @abstractmethod
    def _decrypt_raw(self, ciphertext: CT) -> EncodedPlaintext[RP]:
        """
        Decrypts an ciphertext to its encoded plaintext value.

        :param ciphertext: Ciphertext object containing the ciphertext to be decrypted.
        :return: EncodedPlaintext object containing the encoded decryption of the ciphertext.
        """

    def neg(self, ciphertext: CT) -> CT:
        """
        Negate the underlying plaintext of this ciphertext. I.e. if the original plaintext of this
        ciphertext was 5 this method returns the ciphertext that has -5 as underlying plaintext.

        :param ciphertext: Ciphertext of which the underlying plaintext should be negated.
        :raise NotImplementedError: Raised when negation is not supported by this scheme.
        :return: Ciphertext object corresponding to the negated plaintext.
        """
        raise NotImplementedError("This scheme does not support homomorphic negation")

    def add(
        self,
        ciphertext_1: CT,
        ciphertext_2: Union[CT, PT],
    ) -> CT:
        """
        Add the underlying plaintext value of ciphertext_1 with the (underlying) plaintext value of
        ciphertext_2. Where ciphertext_2 can either be another ciphertext or a plaintext, depending
        on the scheme.

        :param ciphertext_1: First Ciphertext of which the underlying plaintext is added.
        :param ciphertext_2: Either a second Ciphertext of which the underlying plaintext is
            multiplied with the first, or a Plaintext that is added with the underlying plaintext
            of the first Ciphertext.
        :raise NotImplementedError: Raised when addition is not supported by this scheme.
        :return: A Ciphertext containing the encryption of the addition of both values.
        """
        raise NotImplementedError("This scheme does not support homomorphic addition")

    def mul(
        self,
        ciphertext_1: CT,
        ciphertext_2: Union[CT, PT],
    ) -> CT:
        """
        Multiply the underlying plaintext value of ciphertext_1 with the (underlying) plaintext
        value of ciphertext_2. Where ciphertext_2 can either be another ciphertext or a plaintext,
        depending on the scheme.

        :param ciphertext_1: First Ciphertext of which the underlying plaintext is multiplied.
        :param ciphertext_2: Either a second Ciphertext of which the underlying plaintext is
            multiplied with the first, or a Plaintext that is multiplied with the underlying
            plaintext of the first Ciphertext.
        :raise NotImplementedError: Raised when multiplication is not supported by this scheme.
        :return: A Ciphertext containing the encryption of the product of both values.
        """
        raise NotImplementedError(
            "This scheme does not support homomorphic multiplication"
        )

    def pow(self, ciphertext: CT, power: int) -> CT:
        """
        Raise the underlying plaintext value of ciph with the exponent power.

        :param ciphertext: Ciphertext containing the plaintext base.
        :param power: Exponent to which the base should be raised.
        :raise NotImplementedError: Raised when exponentiation is not supported by this scheme.
        :return: Ciphertext containing the value of the underlying plaintext of ciph raised to the
            given power.
        """
        raise NotImplementedError("This scheme does not support homomorphic powers")

    @abstractmethod
    def __eq__(self, other: object) -> bool:
        pass
