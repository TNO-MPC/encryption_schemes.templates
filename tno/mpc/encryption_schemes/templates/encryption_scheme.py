"""
Generic classes used for creating an encryption scheme.
"""
import inspect
from abc import ABC, abstractmethod
from typing import Any, ClassVar, Dict, Generic, Optional, Type, TypeVar, Union, cast

from typing_extensions import Protocol, runtime_checkable

PT = TypeVar("PT")
RP = TypeVar("RP")
KM = TypeVar("KM")
CV = TypeVar("CV")
TCov = TypeVar("TCov", covariant=True)


@runtime_checkable
class SupportsNeg(Protocol[TCov]):
    """
    An ABC with one abstract method __neg__.
    """

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

    def __init__(self) -> None:
        """
        Construct a new EncryptionScheme.
        """
        self.__identifier: Optional[int] = None

    def save_globally(self, overwrite: bool = False) -> None:
        """
        Save this instance in a global list for accessibility using its identifier.

        :param overwrite: overwrite an entry in the global list of the IDs coincide
        :raises KeyError: If the ID already exists in the global list and overwrite is False
        """
        if (
            self.identifier in type(self)._instances
            and type(self)._instances[self.identifier] is not self
            and not overwrite
        ):
            raise KeyError(
                f"A different scheme with the same ID ({self.identifier}) is already saved "
                f"globally. Use "
                f"{type(self).__name__}.from_id or {type(self).__name__}.from_id_arguments  "
                f"if you want to retrieve the "
                f"existing scheme."
            )
        type(self)._instances[self.identifier] = self

    def remove_from_global_list(self) -> None:
        """
        If this instance is saved in the global list, remove it.
        """
        if self.identifier in type(self)._instances:
            type(self)._instances.pop(self.identifier)

    @classmethod
    def clear_instances(cls) -> None:
        """
        Clear the list of globally saved instances
        """
        cls._instances = {}

    @classmethod
    def from_id(cls, identifier: int) -> ES:
        """
        Return the EncryptionScheme with this identifier that is stored in the global list.

        :param identifier: Identifier of the encryption scheme.
        :raise KeyError: If no scheme with this ID was found in the global list.
        :return: EncryptionScheme belonging to this identifier.
        """
        if identifier in cls._instances:
            return cast(ES, cls._instances[identifier])
        raise KeyError(
            "No scheme with this ID has been saved globally. If you want a scheme "
            "to be accessible globally, you need to call save_globally."
        )

    # region Quasi-singleton logic

    @classmethod
    def from_id_arguments(cls: Type[ES], *args: Any, **kwargs: Any) -> ES:
        """
        Function that calls id_from_arguments to obtain an identifier for this scheme and
        then retrieves a scheme from the global list of saved schemes using from_id.

        :param args: regular arguments that would normally go into the constructor
        :param kwargs: regular keyword arguments that would normally go into the constructor
        :return: An EncryptionScheme with the same ID if one has been saved globally
        """
        identifier = cls.id_from_arguments(*args, **kwargs)
        return cls.from_id(identifier=identifier)

    @property
    def identifier(self) -> int:
        """
        Property that returns an identifier for the scheme. It calls id_from_arguments and inspects
        id_from_arguments to see which parameter names are required. It then searches for these
        parameter names in the variables and properties of self and uses their values as input
        to the function. Note that this requires the parameter names to id_from_arguments to
        have the same name as their respective variables/properties in the scheme.

        :raise KeyError: In cast there is a mismatch between the argument names in
            id_from_arguments and the parameter names and properties of the class.
        :return: An identifier of type int
        """
        if self.__identifier is None:
            argument_names = [
                name
                for name in inspect.getfullargspec(self.id_from_arguments)[0]
                if name != "cls"
            ]
            kwargs = {}
            members = self.__dir__()
            for name in argument_names:
                if name not in members:
                    raise KeyError(
                        f"The id_from_arguments function of class {type(self).__name__} has "
                        f"parameter names as input that are not variables of the class. The name "
                        f"that triggered this error was {name}. There is a mismatch between "
                        f"parameter names of "
                        f"id_from_arguments and their respective variable name of the class, so"
                        f" make sure they are the same.\n"
                    )
                value = getattr(self, name)
                if callable(value):
                    raise TypeError(
                        f"{type(self).__name__}.{name} should be a variable or property,"
                        f" but it is a function."
                    )
                kwargs[name] = value
            identifier = self.id_from_arguments(**kwargs)
            self.__identifier = identifier
        return self.__identifier

    @classmethod
    @abstractmethod
    def id_from_arguments(cls, *args: Any, **kwargs: Any) -> int:
        """
        Method that turns the arguments for the constructor into an identifier. This identifier is
        used to find constructor calls that would result in identical schemes.

        :param args: regular arguments
        :param kwargs: regular keyword arguments
        :return: identifier of type int
        """

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
        Decrypts a ciphertext to its encoded plaintext value.

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
        """
        Method that determines whether two EncryptionSchemes are the same

        :param other: EncryptionScheme to be compared to self
        :return: whether they are the same scheme
        """
