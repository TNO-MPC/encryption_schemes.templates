# TNO PET Lab - secure Multi-Party Computation (MPC) - Encryption Schemes - Templates

Generic frameworks for encryption schemes. Currently includes support for:

- Generic encryption scheme (encryption_scheme.py);
- Asymmetric encryption scheme (asymmetric_encryption_scheme.py);
- Symmetric encryption scheme (symmetric_encryption_scheme.py);
- Support for precomputation of randomness (randomized_encryption_scheme.py).

### PET Lab

The TNO PET Lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of PET solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed PET functionalities to boost the development of new protocols and solutions.

The package `tno.mpc.encryption_schemes.templates` is part of the [TNO Python Toolbox](https://github.com/TNO-PET).

_Limitations in (end-)use: the content of this software package may solely be used for applications that comply with international export control laws._  
_This implementation of cryptographic software has not been audited. Use at your own risk._

## Documentation

Documentation of the `tno.mpc.encryption_schemes.templates` package can be found
[here](https://docs.pet.tno.nl/mpc/encryption_schemes/templates/4.1.5).

## Install

Easily install the `tno.mpc.encryption_schemes.templates` package using `pip`:

```console
$ python -m pip install tno.mpc.encryption_schemes.templates
```

_Note:_ If you are cloning the repository and wish to edit the source code, be
sure to install the package in editable mode:

```console
$ python -m pip install -e 'tno.mpc.encryption_schemes.templates'
```

If you wish to run the tests you can use:

```console
$ python -m pip install 'tno.mpc.encryption_schemes.templates[tests]'
```

## Generating prepared randomness for RandomizedEncryptionSchemes

In the encryption process, `RandomizedEncryptionScheme`s require a random number. A typical encryption process generates a large random number, processes it in a way that is specific for (the private key of) the encryption scheme, and used the prepared random value to encrypt a plaintext message. A similarly prepared random value is required to rerandomize a ciphertext. This process of generating and preparing randomness consumes a lot of time and processing power.

Fortunately, the randomness depends only on the encryption scheme and not on the message that is to be encrypted. This makes it possible to prepare randomness a priori. Our library facilitates this process by the concept of "randomness sources". Three specific sources are shipped with the library, but you may define your own `RandomnessSource` by implementing the `tno.mpc.encryption_schemes.templates._randomness_manager.RandomnessSource` protocol. The default sources are:

- `ContextlessSource`, which yields randomness from a source that does not need to be opened or closed (e.g. a list, tuple, function-call, ...).
- `FileSource`, which creates a thread to read a file, store the values in RAM and yield values on request.
- `ProcessSource`, which creates one or more processes that all perform function calls to store a predefined number of return values in RAM and yield on request.

A `RandomizedEncryptionScheme` is configured with a `ContextlessSource` that calls its generating function. However, it is often more efficient to start generating a known amount of randomness earlier in the program execution. For this, one may call `RandomizedEncryptionScheme.boot_generation` which internally initializes and starts a `ProcessSource`, or requests an existing source to generate more randomness (see also below). Other sources can be configured through `RandomizedEncryptionScheme.register_randomness_source`.

### Storing randomness for later use

Naturally, a maximum speed-up during runtime of your main protocol is achieved by generating random values a priori. This looks as follows. First, the key-generating party generates a public-private keypair and shares the public key with the other participants. Now, every player pregenerates the amount of randomness needed for her part of the protocol and stores it in a file. For example, this can be done overnight or during the weekend. When the main protocol is executed, every player uses the same scheme (public key) as communicated before, configures the scheme to use the pregenerated randomness from file, and runs the main protocol without the need to generate randomness for encryption at that time. A minimal example is provided below.

```py
from itertools import count
from pathlib import Path

from tno.mpc.encryption_schemes.templates.random_sources import FileSource
from tno.mpc.encryption_schemes.templates.randomized_encryption_scheme import (
    RandomizedEncryptionScheme,
)

counter = count()


class MyRandomizedEncryptionScheme(RandomizedEncryptionScheme):
    @staticmethod
    def _generate_randomness() -> int:
        """Dummy randomness generator + preprocessing."""
        return next(counter)

    # --- empty definitions for all abstract methods ---
    @classmethod
    def from_security_parameter(cls, *args, **kwargs):
        pass

    @classmethod
    def generate_key_material(cls, *args, **kwargs):
        pass

    @classmethod
    def id_from_arguments(cls, *args, **kwargs):
        pass

    def encode(self, plaintext):
        pass

    def decode(self, encoded_plaintext):
        pass

    def _unsafe_encrypt_raw(self, plaintext):
        pass

    def _decrypt_raw(self, ciphertext):
        pass

    def __eq__(self, *args, **kwargs):
        pass


def pregenerate_randomness_in_weekend(amount: int, path: Path):
    # Initialize scheme, usually with parameters
    generating_scheme = MyRandomizedEncryptionScheme()
    # Generate randomness with two processes
    generating_scheme.boot_randomness_generation(amount, max_workers=2)
    # Save randomness to comma-separated csv
    with open(path, "w") as file:
        for _ in range(amount):
            file.write(f"{generating_scheme.get_randomness()},")
    # Shut down scheme to gracefully close source
    generating_scheme.shut_down()

def use_pregenerated_randomness(amount: int, path: Path):
    # Initialize scheme WITH THE SAME PARAMETERS!
    consuming_scheme = MyRandomizedEncryptionScheme()
    # Configure file as randomness source
    consuming_scheme.register_randomness_source(FileSource(path))
    # Consume randomness from file
    for _ in range(amount):
        print(consuming_scheme.get_randomness())
    # Shut down scheme to gracefully close source
    consuming_scheme.shut_down()


if __name__ == "__main__":
    AMOUNT = 24
    FILE_PATH = Path("randomness.csv")

    pregenerate_randomness_in_weekend(AMOUNT, FILE_PATH)
    use_pregenerated_randomness(AMOUNT, FILE_PATH)
    # result (possibly not in this order): 0 0 1 1 2 2 3 3 4 4 5 5 6 6 7 7 8 8 9 9 10 10 11 11
```
