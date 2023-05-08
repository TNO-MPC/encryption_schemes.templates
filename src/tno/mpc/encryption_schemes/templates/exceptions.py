class SerializationError(Exception):
    """
    Serialization error for encryption schemes.
    """

    def __init__(self) -> None:
        super().__init__(
            "The tno.mpc.communication package has not been installed. "
            "Please install this package before you call the serialization code."
        )
