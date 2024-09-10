"""
This module provides the InstanceManagerMixin class, making it easy to manage instances of a class.

This is useful in serialization/deserialization logic.
"""

from __future__ import annotations

import inspect
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Any, DefaultDict, Generic, TypeVar, cast

if sys.version_info < (3, 11):
    from typing_extensions import Self
else:
    from typing import Self

T = TypeVar("T")


class StrictClassProperty(Generic[T]):  # pylint: disable=too-few-public-methods
    """
    This class provides a property that is scoped to a class rather than an
    instance. This means that the property is shared by all instances of a
    class. This is useful for example to keep track of all instances of a class
    globally.

    It is similar to using `@property` together with `@classmethod`, but
    this has been deprecated as of Python3.11.
    """

    def __init__(self, default_factory: type[T]) -> None:
        """
        Initialize the property with a default factory.

        :param default_factory: The default factory to use for the property.
        """
        self._instances: DefaultDict[Any, T] = defaultdict(default_factory)

    def __get__(self, instance: Any, owner: Any) -> T:
        """
        Get the value of the property for the given class.

        :param instance: The instance of the class for which to get the property.
        :param owner: The class for which to get the property.
        :return: The value of the property for the given class.
        """
        return self._instances[owner]


class InstanceManagerMixin(ABC):
    """
    This Mixin class provides functionality to save instances of a class
    globally and retrieve them using an identifier.

    This is class is used for example by EncryptionScheme. Upon receiving
    a ciphertext, it must be deserialized and the corresponding
    EncryptionScheme instance to which the ciphertext belongs must be found. By
    keeping track of all created EncryptionScheme instances by a unique
    identifier, we can retrieve the EncryptionScheme belonging to a received
    ciphertext.
    """

    _instances: StrictClassProperty[dict[int, Self]] = StrictClassProperty(dict)
    _derived_classes: StrictClassProperty[list[type[Self]]] = StrictClassProperty(list)

    def __init__(self) -> None:
        """
        Initialize the InstanceManagerMixin.

        This method should be called by the constructor of the derived class.
        """
        self.__identifier: int | None = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """
        Constructor for subclasses.

        Ensures that the subclass is registered as a derived class of its superclass.
        """
        base_class_with_instance_manager_mixin_superclass = next(
            base_class
            for base_class in cls.__bases__
            if issubclass(base_class, InstanceManagerMixin)
        )
        base_class_with_instance_manager_mixin_superclass._derived_classes.append(cls)
        return super().__init_subclass__(**kwargs)

    def save_globally(self: Self, overwrite: bool = False) -> None:
        """
        Save this instance in a global list for accessibility using its identifier.

        :param overwrite: overwrite an entry in the global list of the IDs coincide
        :raises KeyError: If the ID already exists in the global list and overwrite is False
        """
        if (
            self.identifier in self._instances
            and self._instances[self.identifier] is not self
            and not overwrite
        ):
            raise KeyError(
                f"A different instance with the same ID ({self.identifier}) is already saved "
                f"globally. Use "
                f"{type(self).__name__}.from_id or {type(self).__name__}.from_id_arguments  "
                f"if you want to retrieve the "
                f"existing instance."
            )
        self._instances[self.identifier] = self

    def remove_from_global_list(self) -> None:
        """
        If this instance is saved in the global list, remove it.
        """
        if self.identifier in self._instances:
            self._instances.pop(self.identifier)

    @classmethod
    def clear_instances(cls, all_types: bool = False) -> None:
        """
        Clear the list of globally saved instances of the current derived
        class.

        :param all_types: also clear instances of other derived classes.
        """
        cls._instances.clear()
        if all_types:
            for scheme_type in cls._derived_classes:
                scheme_type.clear_instances(all_types=True)

    @classmethod
    def from_id(cls, identifier: int) -> Self:
        """
        Return the instance with the given identifier that is stored in the global list.

        :param identifier: Identifier of the instance to retrieve.
        :raise KeyError: If no iinstance with this ID was found in the global list.
        :return: the instance belonging to this identifier.
        """
        if identifier in cls._instances:
            return cast(Self, cls._instances[identifier])
        raise KeyError(
            "No scheme with this ID has been saved globally. If you want a scheme "
            "to be accessible globally, you need to call save_globally."
        )

    @classmethod
    def from_id_arguments(cls, *args: Any, **kwargs: Any) -> Self:
        r"""
        Function that calls id_from_arguments to obtain an identifier for this
        instance and then retrieves an instance from the global list of saved
        schemes using from_id.

        :param \*args: regular arguments that would normally go into the
            constructor
        :param \**kwargs: regular keyword arguments that would normally go into
            the constructor
        :return: An instance with the same ID if one has been saved globally
        """
        identifier = cls.id_from_arguments(*args, **kwargs)
        return cls.from_id(identifier=identifier)

    @property
    def identifier(self) -> int:
        """
        Property that returns an identifier for the instance. It calls
        id_from_arguments and inspects id_from_arguments to see which parameter
        names are required. It then searches for these parameter names in the
        attributes and properties of self and uses their values as input to the
        function. Note that this requires the parameter names to
        id_from_arguments to have the same name as their respective
        attributes/properties in the scheme.

        :raise KeyError: In cast there is a mismatch between the argument names
            in id_from_arguments and the parameter names and properties of the
            class.
        :raise TypeError: At least one argument name from id_from_arguments
            correponds with a callable rather than an attribute or property.
        :raise AttributeError: If the class does not have the attribute
            __identifier, which can happen if the constructor is not called.
        :return: An identifier of type int
        """
        try:
            self.__identifier  # We can't use hasattr because __identifier is mangled
        except AttributeError as e:  # pylint: disable=invalid-name
            raise AttributeError(
                f"{type(self).__name__} has no attribute __identifier. "
                f"Did you forget to call super.__init__() in the constructor?"
            ) from e

        if self.__identifier is None:
            argument_names = [
                name
                for name in inspect.getfullargspec(self.id_from_arguments)[0]
                if name != "cls"
            ]
            kwargs = {}
            members = dir(self)
            for name in argument_names:
                if name not in members:
                    raise KeyError(
                        f"The id_from_arguments function of class {type(self).__name__} has "
                        f"parameter names as input that are not attributes of the class. The name "
                        f"that triggered this error was {name}. There is a mismatch between "
                        f"parameter names of "
                        f"id_from_arguments and their respective attribute name of the class, so"
                        f" make sure they are the same.\n"
                    )
                value = getattr(self, name)
                if callable(value):
                    raise TypeError(
                        f"{type(self).__name__}.{name} should be an attribute or property,"
                        f" but it is a callable."
                    )
                kwargs[name] = value
            identifier = self.id_from_arguments(**kwargs)
            self.__identifier = identifier
        return self.__identifier

    @classmethod
    @abstractmethod
    def id_from_arguments(cls, *args: Any, **kwargs: Any) -> int:
        r"""
        Method that turns the arguments for the constructor into an identifier.
        This identifier is used to find constructor calls that would result in
        identical instances.

        :param \*args: regular arguments
        :param \**kwargs: regular keyword arguments
        :return: identifier of type int
        """
