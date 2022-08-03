"""
File containing all tests regarding the storing of encryption schemes and the generation of the
id that is used for that purpose.
"""

from __future__ import annotations

from abc import ABC
from typing import Any, Type, Union, cast

import pytest

from tno.mpc.encryption_schemes.templates.encryption_scheme import (
    CT,
    KM,
    PT,
    RP,
    Ciphertext,
    EncodedPlaintext,
    EncryptionScheme,
)


@pytest.mark.parametrize("identifier", list(range(10)))
def test_id_generation_no_id_from_arguments(
    identifier: int,
) -> None:
    """
    Test to check if the right error is thrown when the id_from_arguments method is not present.

    :param identifier: Identifier to be used for this scheme.
    """
    with pytest.raises(TypeError):
        _ = TestSchemeNoFunc(dummy_value=identifier)  # type: ignore


@pytest.mark.parametrize("identifier", list(range(10)))
def test_id_generation_with_id_from_arguments_wrong_var_name(
    identifier: int,
) -> None:
    """
    Test to check if the right error is thrown when the id_from_arguments method uses wrong
    argument names.

    :param identifier: Identifier to be used for this scheme.
    """
    test_scheme = TestSchemeWithFuncWrongVarName(dummy_value=identifier)
    with pytest.raises(KeyError):
        _ = test_scheme.identifier


@pytest.mark.parametrize("identifier", list(range(10)))
def test_id_generation_with_id_from_arguments_right_var_name(
    identifier: int,
) -> None:
    """
    Test to check if the right id is given to the EncryptionScheme when id_from_arguments is
    implemented correctly.

    :param identifier: Identifier to be used for this scheme.
    """
    test_scheme = TestSchemeWithFuncRightVarName(dummy_value=identifier)
    assert test_scheme.identifier == identifier


@pytest.mark.parametrize("identifier", list(range(10)))
def test_saving_globally(
    identifier: int,
) -> None:
    """
    Test to check if the EncryptionScheme is saved correctly globally when id_from_arguments is
    implemented correctly. Also check overwrite warnings in case that the should or should not be
    given. Next to this, removal of the global list is checked.

    :param identifier: Identifier to be used for this scheme.
    """
    test_scheme_1 = TestSchemeWithFuncRightVarName(dummy_value=identifier)
    test_scheme_2 = TestSchemeWithFuncRightVarName(dummy_value=identifier)
    with pytest.raises(KeyError):
        _ = TestSchemeWithFuncRightVarName.from_id(identifier)

    assert len(TestSchemeWithFuncRightVarName._instances) == 0

    test_scheme_1.save_globally(overwrite=False)
    assert len(TestSchemeWithFuncRightVarName._instances) == 1
    assert TestSchemeWithFuncRightVarName._instances[identifier] is test_scheme_1
    assert TestSchemeWithFuncRightVarName.from_id(identifier) is test_scheme_1
    assert (
        TestSchemeWithFuncRightVarName.from_id_arguments(dummy_value=identifier)
        is test_scheme_1
    )

    # This should do nothing
    test_scheme_1.save_globally(overwrite=False)
    assert len(TestSchemeWithFuncRightVarName._instances) == 1
    assert TestSchemeWithFuncRightVarName._instances[identifier] is test_scheme_1
    assert TestSchemeWithFuncRightVarName.from_id(identifier) is test_scheme_1
    assert (
        TestSchemeWithFuncRightVarName.from_id_arguments(dummy_value=identifier)
        is test_scheme_1
    )

    # ensure that test_scheme_1 does not get overwritten and a proper exception is thrown
    with pytest.raises(KeyError):
        test_scheme_2.save_globally(overwrite=False)

    test_scheme_2.save_globally(overwrite=True)
    # The entry of identifier in the global list should be overwritten now
    assert len(TestSchemeWithFuncRightVarName._instances) == 1
    assert TestSchemeWithFuncRightVarName._instances[identifier] is test_scheme_2
    assert TestSchemeWithFuncRightVarName.from_id(identifier) is test_scheme_2
    assert (
        TestSchemeWithFuncRightVarName.from_id_arguments(dummy_value=identifier)
        is test_scheme_2
    )

    test_scheme_3 = TestSchemeWithFuncRightVarName(dummy_value=identifier + 1)
    # the global list should be the same
    assert len(TestSchemeWithFuncRightVarName._instances) == 1
    assert TestSchemeWithFuncRightVarName._instances[identifier] is test_scheme_2
    assert TestSchemeWithFuncRightVarName.from_id(identifier) is test_scheme_2
    assert (
        TestSchemeWithFuncRightVarName.from_id_arguments(dummy_value=identifier)
        is test_scheme_2
    )

    test_scheme_3.save_globally()
    # check if the scheme is saved properly when another scheme is stored
    assert len(TestSchemeWithFuncRightVarName._instances) == 2
    assert TestSchemeWithFuncRightVarName._instances[identifier] is test_scheme_2
    assert TestSchemeWithFuncRightVarName.from_id(identifier) is test_scheme_2
    assert (
        TestSchemeWithFuncRightVarName.from_id_arguments(dummy_value=identifier)
        is test_scheme_2
    )
    assert TestSchemeWithFuncRightVarName._instances[identifier + 1] is test_scheme_3
    assert TestSchemeWithFuncRightVarName.from_id(identifier + 1) is test_scheme_3
    assert (
        TestSchemeWithFuncRightVarName.from_id_arguments(dummy_value=identifier + 1)
        is test_scheme_3
    )

    test_scheme_3.remove_from_global_list()
    # check if removal works properly
    assert len(TestSchemeWithFuncRightVarName._instances) == 1
    assert TestSchemeWithFuncRightVarName._instances[identifier] is test_scheme_2
    assert TestSchemeWithFuncRightVarName.from_id(identifier) is test_scheme_2
    assert (
        TestSchemeWithFuncRightVarName.from_id_arguments(dummy_value=identifier)
        is test_scheme_2
    )
    test_scheme_3.save_globally()
    TestSchemeWithFuncRightVarName.clear_instances()
    assert len(TestSchemeWithFuncRightVarName._instances) == 0


class DummyScheme(EncryptionScheme[Any, Any, Any, Any, Any], ABC):
    """
    Dummy encryption scheme only used for subclassing by test classes that don't use any real
    encryption functionality.
    """

    @classmethod
    def from_security_parameter(  # type:ignore[override]
        cls: Type[DummyScheme], security_parameter: int
    ) -> DummyScheme:
        """
        Dummy

        :param security_parameter: -
        :raise NotImplementedError: always
        :return: -
        """

        raise NotImplementedError()

    @staticmethod
    def generate_key_material(*args: Any, **kwargs: Any) -> KM:
        r"""
        Stub

        :param \*args: -
        :param \**kwargs: -
        :return: -
        """

    def encode(self, plaintext: PT) -> EncodedPlaintext[RP]:
        """
        Dummy encoding of plaintext.

        :param plaintext: Plaintext to encode.
        :return: Dummy encoding of plaintext.
        """
        return EncodedPlaintext(value=cast(RP, plaintext), scheme=self)

    def decode(  # pylint: disable=no-self-use
        self, encoded_plaintext: EncodedPlaintext[RP]
    ) -> PT:
        """
        Decoding of dummy encoded plaintext.

        :param encoded_plaintext: Encoded plaintext to be decoded.
        :return: Decoded plaintext
        """
        return cast(PT, encoded_plaintext.value)

    def _encrypt_raw(
        self, plaintext: EncodedPlaintext[RP]
    ) -> Ciphertext[Any, Any, Any, Any]:
        """
        Dummy encryption of encoded plaintext.

        :param plaintext: Plaintext to encrypt
        :return: Raw dummy encryption of plaintext.
        """
        return Ciphertext(raw_value=plaintext.value, scheme=self)

    def _decrypt_raw(self, ciphertext: CT) -> EncodedPlaintext[RP]:
        """
        Decryption of dummy encrypted ciphertext.

        :param ciphertext: Ciphertext to be decrypted
        :return: Dummy encoded decryption of the given ciphertext.
        """
        return EncodedPlaintext(value=ciphertext.value, scheme=self)

    def neg(self, ciphertext: CT) -> CT:
        """
        Stub

        :param ciphertext: -
        :return: -
        """

    def add(self, ciphertext_1: CT, ciphertext_2: Union[CT, PT]) -> CT:
        """
        Stub

        :param ciphertext_1: -
        :param ciphertext_2: -
        :return: -
        """

    def mul(self, ciphertext_1: CT, ciphertext_2: Union[CT, PT]) -> CT:
        """
        Stub

        :param ciphertext_1: -
        :param ciphertext_2: -
        :return: -
        """

    def pow(self, ciphertext: CT, power: int) -> CT:
        """
        Stub

        :param ciphertext: -
        :param power: -
        :return: -
        """

    def __eq__(self, other: object) -> bool:
        """
        Stub

        :param other: -
        :return: -
        """


class TestSchemeNoFunc(DummyScheme):
    """
    Dummy encryption scheme without id_from_arguments method.
    """

    def __init__(self, dummy_value: int) -> None:
        super().__init__()
        self.dummy_value = dummy_value


class TestSchemeWithFuncWrongVarName(DummyScheme):
    """
    Dummy encryption scheme with id_from_arguments method that has an argument name different
    from the attribute.
    """

    def __init__(self, dummy_value: int) -> None:
        self.dummy = dummy_value
        super().__init__()

    @classmethod
    def id_from_arguments(cls, dummy_value: int) -> int:  # type: ignore[override]
        """
        Generate a unique id from the dummy_value attribute of this scheme.
        Note: dummy_value is not the attribute of this scheme (that is dummy), this should thus
        fail.

        :param dummy_value: Dummy value.
        :return: Numeric id
        """
        return dummy_value


class TestSchemeWithFuncRightVarName(DummyScheme):
    """
    Dummy encryption scheme with id_from_arguments method that has an argument name agreeing
    from the attribute. In other words, this dummy scheme is correct.
    """

    def __init__(self, dummy_value: int) -> None:
        self.dummy_value = dummy_value
        super().__init__()

    @classmethod
    def id_from_arguments(cls, dummy_value: int) -> int:  # type: ignore[override]
        """
        Generate a unique id from the dummy_value attribute of this scheme.

        :param dummy_value: Dummy value.
        :return: Numeric id
        """
        return dummy_value
