"""
Generic classes used for creating an asymmetric encryption scheme.
"""

from abc import ABC, abstractmethod
import inspect
from typing import Any, cast, Generic, Optional, Tuple, Type, TypeVar

from .encryption_scheme import CT, CV, EncryptionScheme, KM, PT, RP


class PublicKey:
    """
    Public Key of an AsymmetricEncryptionScheme.

    This should be subclassed for every AsymmetricEncryptionScheme.
    """


class SecretKey:
    """
    Secret Key of an AsymmetricEncryptionScheme.

    This should be subclassed for every AsymmetricEncryptionScheme.
    """


PK = TypeVar("PK", bound=PublicKey)
SK = TypeVar("SK", bound=SecretKey)
AE = TypeVar(
    "AE", bound="AsymmetricEncryptionScheme[Any, Any, Any, Any, Any, Any, Any]"
)


class AsymmetricEncryptionScheme(
    Generic[KM, PT, RP, CV, CT, PK, SK], EncryptionScheme[KM, PT, RP, CV, CT], ABC
):
    """
    Abstract base class for an AsymmetricEncryptionScheme. Subclass of EncryptionScheme.
    """

    @classmethod
    def from_security_parameter(cls: Type[AE], *args: Any, **kwargs: Any) -> AE:
        """
        Generate a new AsymmetricEncryptionScheme from a security parameter.

        :param args: Security parameter(s) and optional extra arguments for the EncryptionScheme
            constructor.
        :param kwargs: Security parameter(s) and optional extra arguments for the EncryptionScheme
            constructor.
        :return: A new EncryptionScheme.
        """
        gen_names = inspect.getfullargspec(cls.generate_key_material)[0]
        gen_kwargs = {}
        init_kwargs = {}
        for kwarg, val in kwargs.items():
            if kwarg in gen_names:
                gen_kwargs[kwarg] = val
            else:
                init_kwargs[kwarg] = val

        public_key, secret_key = cast(
            Tuple[PK, SK], cls.generate_key_material(*args, **gen_kwargs)
        )
        return cls(public_key, secret_key, **init_kwargs)

    @classmethod
    def from_public_key(cls: Type[AE], public_key: PK, **kwargs: Any) -> AE:
        """
        Generate a new AsymmetricEncryptionScheme from a public key (e.g. when received from another
        party).

        :param public_key: The PublicKey of this scheme instantiation.
            constructor.
        :param kwargs: Optional extra arguments for the EncryptionScheme constructor.
        :return: A new EncryptionScheme.
        """
        return cls(public_key=public_key, secret_key=None, **kwargs)

    @classmethod
    def get_instance_from_public_key(
        cls: Type[AE], public_key: PublicKey, **kwargs: Any
    ) -> AE:
        """
        Generate a new AsymmetricEncryptionScheme from a public key (e.g. when received from another
        party).

        :param public_key: The PublicKey of this scheme instantiation.
            constructor.
        :param kwargs: Optional extra arguments for the EncryptionScheme constructor.
        :return: A new EncryptionScheme.
        """
        return cls.get_instance(public_key=public_key, secret_key=None, **kwargs)

    # region Quasi-Singleton logic

    @classmethod
    def get_instance_from_sec_param(
        cls: Type[AE], *sec_params: Any, **kw_sec_params: Any
    ) -> AE:
        """
        Function that makes sure that when an instance of the given class has already instantiated
        before with similar security parameter, a reference is returned to that scheme

        :param sec_params: positional security parameters
        :param kw_sec_params: keyword security parameters
        :return: Either a newly instantiated scheme or a reference to an already existing scheme
        """
        identifier = cls.id_from_sec_param(*sec_params, **kw_sec_params)
        if identifier in cls._instances:
            instance = cls._instances[identifier]
            # assert correct class, since _instances is shared among all EncryptionSchemes
            assert isinstance(instance, cls)
            return instance
        # else
        instance = cls.from_security_parameter(*sec_params, **kw_sec_params)
        cls._instances[identifier] = instance
        return instance

    @classmethod
    def id_from_sec_param(cls, *sec_params: Any, **kw_sec_params: Any) -> int:
        """
        Function that returns an identifier based on the security parameters

        :param sec_params: positional security parameters
        :param kw_sec_params: keyword security parameters
        :return: identifier of type int
        """
        return hash(
            tuple("from sec params")
            + tuple(sec_params)
            + tuple(kw_sec_params[i] for i in sorted(kw_sec_params))
        )

    # endregion

    def __init__(self, public_key: PK, secret_key: Optional[SK], **_kwargs: Any):
        """
        Construct an AsymmetricEncryptionScheme with the given keypair.

        :param public_key: Asymmetric PublicKey.
        :param secret_key: Asymmetric SecretKey, might be None when the SecretKey is unknown.
        :param kwargs: Possible extra parameters for this scheme.
        """
        self.__pk = public_key
        self.__sk = secret_key
        EncryptionScheme.__init__(self)

    @staticmethod
    @abstractmethod
    def generate_key_material(*args: Any, **kwargs: Any) -> KM:
        """
        Method to generate key material (PublicKey and SecretKey) for this scheme.

        :param args: Required arguments to generate said key material.
        :param kwargs: Required arguments to generate said key material.
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
    def secret_key(self) -> Optional[SK]:
        """
        SecretKey of this instantiation of the scheme.

        :return: SecretKey of this instantiation, or None when it is unknown.
        """
        return self.__sk
