"""
Generic classes used for creating a symmetric encryption scheme.
"""

from __future__ import annotations

import inspect
from abc import ABC
from secrets import randbits
from typing import Any, List, TypeVar

from .encryption_scheme import CT, CV, PT, RP, EncryptionScheme

Bits = List[int]


class SymmetricKey:
    """
    Class for storing and generating symmetric key material
    """

    @classmethod
    def from_sec_param(cls, sec_param: int) -> SymmetricKey:
        """
        Class method that generates a uniformly random secret key

        :param sec_param: bit security of the key to be generated
        :return: uniformly random symmetric key with bit security equal to sec_param
        """
        rand_int = randbits(sec_param)
        return cls(bin(rand_int))

    @classmethod
    def to_bits(cls, to_convert: bytes | str) -> Bits:
        """
        Class method that converts alternate representations of a symmetric key to the right format

        :param to_convert: variable of type bytes or str (of format '0b{0,1}*') to be converted
        :return: list of integers in that are either 0 or 1
        """
        if isinstance(to_convert, bytes):
            return [i - 48 for i in to_convert]
        return [int(i) for i in to_convert[2:]]

    def __init__(self, key_value: str | int | Bits):
        if isinstance(key_value, list):
            if not all(x in [0, 1] for x in key_value):
                raise ValueError("The elements in the provided list are not bits")
            self.value = int("".join([str(i) for i in key_value]), 2)
            self.bits = key_value
        elif isinstance(key_value, int):
            self.value = key_value
            self.bits = self.to_bits(bin(key_value))
        elif isinstance(key_value, str):
            if not key_value[:2] == "0b":
                raise ValueError("This string is not of the format '0b{0,1}*'.")
            self.value = int(key_value[2:], 2)
            self.bits = self.to_bits(key_value)
        else:
            raise TypeError(
                f"Expected input to be either a binary string, integer or list of bits, not"
                f" {type(key_value)}."
            )
        self.security_parameter = len(self.bits)

    def serialize(self) -> dict[str, int]:
        """
        Serialize this symmetric key.

        :return: Dictionary object containing the value of this key.
        """
        return {"int_value": self.value}

    @classmethod
    def deserialize(cls, json: dict[str, int]) -> SymmetricKey:
        """
        Construct this key from its serialization.

        :param json: Serialization of this key.
        :return: An initialized version of this key.
        """
        return cls(json["int_value"])


SK = TypeVar("SK", bound=SymmetricKey)
SE = TypeVar("SE", bound="SymmetricEncryptionScheme[Any, Any, Any, Any, Any]")


class SymmetricEncryptionScheme(EncryptionScheme[SK, PT, RP, CV, CT], ABC):
    """
    Abstract base class for a SymmetricEncryptionScheme. Subclass of EncryptionScheme.
    """

    @classmethod
    def from_security_parameter(cls: type[SE], *args: Any, **kwargs: Any) -> SE:
        r"""
        Generate a new SymmetricEncryptionScheme from a security parameter.

        :param \*args: Security parameter(s) and optional extra arguments for the
            SymmetricEncryptionScheme constructor.
        :param \**kwargs: Security keyword parameter(s) and optional extra arguments for the
            SymmetricEncryptionScheme constructor.
        :return: Symmetric cryptographic scheme
        """
        gen_names = inspect.getfullargspec(cls.generate_key_material)[0]
        gen_kwargs = {}
        init_kwargs = {}
        for kwarg, val in kwargs.items():
            if kwarg in gen_names:
                gen_kwargs[kwarg] = val
            else:
                init_kwargs[kwarg] = val

        symmetric_key = cls.generate_key_material(*args, **gen_kwargs)
        return cls(symmetric_key, **init_kwargs)

    def __init__(self, key: SK, *_args: Any, **_kwargs: Any) -> None:
        r"""
        Construct a SymmetricEncryptionScheme with the given key.

        :param key: Symmetric key.
        :param \*_args: Possible extra parameters for this scheme.
        :param \**_kwargs: Possible extra keyword parameters for this scheme.
        """
        self.__key = key
        EncryptionScheme.__init__(self)

    @staticmethod
    def generate_key_material(  # type: ignore[override]
        bit_length: int,
    ) -> SymmetricKey:
        r"""
        Method to generate key material (SymmetricKey) for this scheme.

        :param bit_length: Desired bit security of the secret key
        :return: The SymmetricKey that was generated.
        """
        return SymmetricKey.from_sec_param(bit_length)

    def __eq__(self, other: object) -> bool:
        """
        Compare equality of two SymmetricEncryptionSchemes

        :param other: The other object to compare with.
        :raise TypeError: When the type of the other object is not the same is of this scheme.
        :return: Boolean value representing (in)equality of self and other.
        """
        if not isinstance(other, type(self)):
            raise TypeError(
                f"Expected comparison with the same type symmetric encryption scheme, not"
                f" {type(other)}"
            )
        return isinstance(other, type(self)) and self.__key == other.key

    def serialize(self, **_kwargs: Any) -> dict[str, dict[str, int]]:
        r"""
        Serialize the key of this encryption scheme.

        :param \**_kwargs: Unused parameters to adhere to
            tno.mpc.communication.SupportsSerializiation protocol.
        :return: Serialized key.
        """
        return {"key": self.__key.serialize()}

    @classmethod
    def deserialize(
        cls: type[SE], json: dict[str, dict[str, int]], **_kwargs: Any
    ) -> SE:
        r"""
        Construct this scheme from the serialization.

        :param json: Serialization of this scheme.
        :param \**_kwargs: Optional extra keyword arguments.
        :return: An initialized version of this scheme.
        """
        key = SymmetricKey.deserialize(json["key"])
        return cls(key)

    @property
    def key(self) -> SK:
        """
        SymmetricKey of this instantiation of the scheme.

        :return: SymmetricKey of this instantiation.
        """
        return self.__key
