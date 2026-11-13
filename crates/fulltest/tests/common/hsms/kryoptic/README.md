# Kryoptic

## About

[Kryoptic](https://github.com/latchset/kryoptic/) is a software HSM written
in Rust. The Rust [Cryptoki](https://github.com/parallaxsecond/rust-cryptoki)
interface to PKCS#11 modules tests against both SoftHSMv2 and Kryoptic.

## Interfaces offered

- PKCS#11 v2 and v3.

## Tested versions

- Fedora RPM v1.5.4.
- Cascade-HSM-Bridge reports `Loaded Kryoptic PKCS#11 library v0.0 supporting Cryptoki v3.2: Kryoptic PKCS11 Module`.

## Known issues

- None.

## Testing prerequisites

- Install Kryoptic, via an O/S package or from sources.
- Install `pkcs11-tool` from the [OpenSC](https://github.com/OpenSC/OpenSC)
  project, via an O/S package or from sources.
- [OPTIONAL] Set environment variable `KRYOPTIC_PATH` to the location of
  `libkryoptic_pkcs11.so` if the test is not able to find it.

## Running the test

cargo run --package fulltest -- kryoptic

## How Kryoptic works

Kryoptic consists only of its PKCS#11 module, configuration file and an
SQLite database that it uses to store token data. Cryptography is provided
by the OpenSSL library.

Kryoptic depends on the 3rd party tool `pkcs11-tool` for initializing tokens.

## How the test works

The test will:
- Create a temporary directory.
- Write a Kryoptic configuration file in $TMPDIR that directs Kryoptic to
  store token data under $TMPDIR, and configures Kryoptic to treat EC point
  data as DER encoded (rather than the default of raw bytes), as this is how
  other tested PKCS#11 modules behave.
- Set the `KRYOPTIC_CONF` environment variable to the location of the custom
  configuration file, thereby guiding Kryoptic to use the test configuration.
- Invoke `pkcs11-tool` to initialize a token with a known SO PIN and PIN.
- Configure Cascade-HSM-Bridge to load the Kryoptic PKCS#11 module.
- Execute KMIP operations against Cascade-HSM-Bridge which in turn will
  execute PKCS#11 functions in the loaded Kryoptic PKCS#11 module.
