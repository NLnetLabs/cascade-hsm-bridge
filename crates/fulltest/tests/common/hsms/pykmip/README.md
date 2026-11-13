# PyKMIP

## About

[PyKMIP](https://github.com/OpenKMIP/PyKMIP) is a _"PyKMIP is a Python
implementation of the Key Management Interoperability Protocol (KMIP)"_.
Its [documentation](https://pykmip.readthedocs.io/en/latest/server.html) warns
that:

> The PyKMIP server is intended for testing and demonstration purposes
> only. It is not a replacement for a secure, hardened, hardware-based
> key management appliance. It should not be used in a production-level
> environment, nor for critical operations.

## Interfaces offered

- KMIP 1.x.

## Tested versions

- 0.11.0.

## Known issues

- No support for ECDSAP256SHA256, ECDSAP384SHA384, Ed25519 or Ed448.
- Key revocation fails with error: `IllegalOperation: The object is not active and cannot be revoked with reason other tha
n KEY_COMPROMISE`

## Testing prerequisites

- The Python 3 tools `virtualenv` and `pip` must be installed.

## Running the test

- Run the test: `cargo run --package fulltest -- pykmip`

## How PyKMIP works

PyKMIP is a Python implementation of a KMIP TCP+TLS server that uses a SQLite
database that it manages.

## How the test works

The test will:
- Create a temporary directory.
- Generate self-signed TLS certificates for use by PyKMIP (required).
- Write a PyKMIP configuration file in $TMPDIR that configures PyKMIP to use
  the generated certificates and to store its database file under $TMPDIR.
- Generates a simple Python script that runs PyKMIP using the generated
  configuration file and directing it to a log to a file under $TMPDIR.
- Uses `virtualenv` and `pip` to install PyKMIP using Python 3.11 (at the
  time of writing PyKMIP was incompatible with newer versions of Python due
  a to a TLS API change that was made in Python).
- Waits upto 5 seconds for TCP+TLS connection to PyKMIP to be established
  successfully.
- Execute KMIP operations against PyKMIP directly.
