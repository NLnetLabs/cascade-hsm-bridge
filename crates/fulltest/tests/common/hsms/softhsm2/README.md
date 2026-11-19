# SoftHSMv2

## About

[SoftHSM](https://www.softhsm.org/) is a software HSM written in
C++. It was created as part of the OpenDNSSEC project. The Rust
[Cryptoki](https://github.com/parallaxsecond/rust-cryptoki) interface to
PKCS#11 modules tests against both SoftHSMv2 and Kryoptic.

## Interfaces offered

- PKCS#11 v2 and v3.

## Tested versions

- Fedora RPM v2.7.0.
- Cascade-HSM-Bridge reports `Loaded SoftHSM PKCS#11 library v2.7 supporting Cryptoki v3.2: Implementation of PKCS11`.

## Known issues

- None.

## Testing prerequisites

- Install SoftHSM, via an O/S package or from sources.
- [OPTIONAL] Set environment variable `SOFTHSM2_PATH` to the location of
  `libsofthsm2.so` if the test is not able to find it.

## Running the test

cargo run --package fulltest -- softhsmv2

# How SoftHSM works

SoftHSM consists only of its PKCS#11 module, configuration file, and a token
data directory. Cryptography is provided by the OpenSSL or Botan library.
There is no other database or backend server that the module talks to, all
logic is contained within the PKCS#11 module.

SoftHSM provides its own tool, `softhsm2-util`, for initializing tokens.

## How the test works

The test will:
- Create a temporary directory.
- Write a SoftHSM configuration file in $TMPDIR that directs SoftHSM to
  store token data under $TMPDIR.
- Set the `SOFTHSM2_CONF` environment variable to the location of the custom
  configuration file, thereby guiding SoftHSM to use the test configuration.
- Invoke `softhsm2-util` to initialize a token with a known label, SO PIN and
  PIN.
- Configure Cascade-HSM-Bridge to load the SoftHSM PKCS#11 module.
- Execute KMIP operations against Cascade-HSM-Bridge which in turn will
  execute PKCS#11 functions in the loaded SoftHSM PKCS#11 module.
