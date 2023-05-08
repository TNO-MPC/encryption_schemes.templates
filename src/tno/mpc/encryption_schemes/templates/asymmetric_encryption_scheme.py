"""
Generic classes used for creating an asymmetric encryption scheme.
"""
from __future__ import annotations

import inspect
import sys
from abc import ABC, abstractmethod
from typing import Any, Generic, Tuple, TypeVar, cast

from .encryption_scheme import CT, CV, KM, PT, RP, EncryptionScheme

if sys.version_info < (3, 8):
    from typing_extensions import Protocol, Self
elif sys.version_info < (3, 11):
    from typing import Protocol

    from typing_extensions import Self
else:
    from typing import Protocol, Self


class PublicKey(Protocol):
    """
    Public Key of an AsymmetricEncryptionScheme.

    This should be subclassed for every AsymmetricEncryptionScheme.
    """

    def serialize(self, **_kwargs: Any) -> Any:
        r"""
        Serialization function for public keys, which will be passed to the communication module.

        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this PublicKey.
        """

    @staticmethod
    def deserialize(obj: Any, **_kwargs: Any) -> PublicKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module.

        :param obj: serialized version of a PublicKey.
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized PublicKey from the given dict.
        """


class SecretKey(Protocol):
    """
    Secret Key of an AsymmetricEncryptionScheme.

    This should be subclassed for every AsymmetricEncryptionScheme.
    """

    def serialize(self, **_kwargs: Any) -> Any:
        r"""
        Serialization function for secret keys, which will be passed to the communication module.

        :param \**_kwargs: Optional extra keyword arguments.
        :raise SerializationError: When communication library is not installed.
        :return: serialized version of this SecretKey.
        """

    @staticmethod
    def deserialize(obj: Any, **_kwargs: Any) -> SecretKey:
        r"""
        Deserialization function for public keys, which will be passed to the communication module.

        :param obj: serialized version of a SecretKey.
        :param \**_kwargs: optional extra keyword arguments
        :raise SerializationError: When communication library is not installed.
        :return: Deserialized SecretKey from the given dict.
        """


PK = TypeVar("PK", bound=PublicKey)
SK = TypeVar("SK", bound=SecretKey)


class AsymmetricEncryptionScheme(
    Generic[KM, PT, RP, CV, CT, PK, SK], EncryptionScheme[KM, PT, RP, CV, CT], ABC
):
    """
    Abstract base class for an AsymmetricEncryptionScheme. Subclass of EncryptionScheme.
    """

    @classmethod
    def from_security_parameter(cls, *args: Any, **kwargs: Any) -> Self:
        r"""
        Generate a new AsymmetricEncryptionScheme from a security parameter. Note that regular
        arguments will be passed to the generate_key_material  method, so all parameter that are
        required for the constructor should be passed as keyword arguments.

        :param \*args: Security parameter(s) for key generation.
        :param \**kwargs: Security parameter(s) and optional extra arguments for the constructor.
        :raises ValueError: If a keyword argument is not valid for key generation or the
            constructor.
        :return: A new EncryptionScheme.
        """
        gen_names = inspect.getfullargspec(cls.generate_key_material)[0]
        init_names = [
            name for name in inspect.getfullargspec(cls.__init__)[0] if name != "self"
        ]
        gen_kwargs = {}
        init_kwargs = {}
        for kwarg, val in kwargs.items():
            if kwarg in gen_names:
                # arguments used for generating key material
                gen_kwargs[kwarg] = val
            elif kwarg in init_names:
                # arguments used in the __init__ method
                init_kwargs[kwarg] = val
            else:
                raise ValueError(
                    f"The keyword arguments should either be used for key generation, "
                    f"or passed to the constructor, but parameter with name {kwarg} "
                    f"is not present in either."
                )

        public_key, secret_key = cast(
            Tuple[PK, SK], cls.generate_key_material(*args, **gen_kwargs)
        )
        return cls(public_key, secret_key, **init_kwargs)

    @classmethod
    def from_public_key(cls, public_key: PK, **kwargs: Any) -> Self:
        r"""
        Generate a new AsymmetricEncryptionScheme from a public key (e.g. when received from another
        party) and possibly additional parameters.

        :param public_key: The PublicKey of this scheme instantiation.
        :param \**kwargs: Optional extra keyword arguments for the constructor.
        :return: A new EncryptionScheme.
        """
        return cls(public_key=public_key, secret_key=None, **kwargs)

    def __init__(
        self,
        public_key: PK,
        secret_key: SK | None,
        *_args: Any,
        **_kwargs: Any,
    ) -> None:
        r"""
        Construct an AsymmetricEncryptionScheme with the given keypair and optional keyword
        arguments. All keyword arguments are combined with the public key to create an ID, so all
        the __init__ of a custom subclass of AsymmetricEncryptionScheme should pass all their
        parameter values as keyword arguments to this __init__ for the ID generation to work
        properly. If this does not happen, then schemes might be considered equal when they are
        totally different.

        :param public_key: Asymmetric PublicKey.
        :param secret_key: Asymmetric SecretKey, might be None when the SecretKey is unknown.
        :param \*_args: Optional extra arguments for the constructor of a concrete implementation.
        :param \**_kwargs: Optional extra keyword arguments for the constructor of a concrete
            implementation.
        """
        self.__pk = public_key
        self.__sk = secret_key

        EncryptionScheme.__init__(self)

    @classmethod
    @abstractmethod
    def generate_key_material(cls, *args: Any, **kwargs: Any) -> KM:
        r"""
        Method to generate key material (PublicKey and SecretKey) for this scheme.

        :param \*args: Required arguments to generate said key material.
        :param \**kwargs: Required arguments to generate said key material.
        :return: Tuple containing first the PublicKey of this scheme and then the SecretKey.
        """

    @property
    def public_key(self) -> PK:
        """
        PublicKey of this instantiation of the scheme.

        :return: PublicKey of this instantiation.
        """
        return self.__pk

    @property
    def secret_key(self) -> SK | None:
        """
        SecretKey of this instantiation of the scheme.

        :return: SecretKey of this instantiation, or None when it is unknown.
        """
        return self.__sk
