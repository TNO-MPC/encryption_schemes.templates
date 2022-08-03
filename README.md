# TNO MPC Lab - Encryption Schemes - Templates

The TNO MPC lab consists of generic software components, procedures, and functionalities developed and maintained on a regular basis to facilitate and aid in the development of MPC solutions. The lab is a cross-project initiative allowing us to integrate and reuse previously developed MPC functionalities to boost the development of new protocols and solutions.

The package tno.mpc.encryption_schemes.templates is part of the TNO Python Toolbox.

*Limitations in (end-)use: the content of this software package may solely be used for applications that comply with international export control laws.*  
*This implementation of cryptographic software has not been audited. Use at your own risk.*

## Documentation

Documentation of the tno.mpc.encryption_schemes.templates package can be found [here](https://docs.mpc.tno.nl/encryption_schemes/templates/3.0.0).

## Install

Easily install the tno.mpc.encryption_schemes.templates package using pip:
```console
$ python -m pip install tno.mpc.encryption_schemes.templates
```

If you wish to run the tests you can use:
```console
$ python -m pip install 'tno.mpc.encryption_schemes.templates[tests]'
```

## Usage

Generic frameworks for encryption schemes. Currently includes support for:

* Generic encryption scheme (`encryption_scheme.py`);
* Asymmetric encryption scheme (`asymmetric_encryption_scheme.py`);
* Symmetric encryption scheme (`symmetric_encryption_scheme.py`);
* Support for precomputation of randomness (`randomized_encryption_scheme.py`).

