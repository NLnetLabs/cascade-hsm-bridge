# Securosys CloudHSM

## About

The [Securosys CloudHSM](https://www.securosys.com/cloud-security/cloudhsm-overview)
is:

> A fully managed Hardware Security Module (HSM) service that enables you to
> securely generate, store, and use cryptographic keys without managing HSM
> infrastructure yourself.

Securosys provide a demo server at:

- KMIP: kmip-server.cloudshsm.com
- Web UI: https://kms.cloudshsm.com/

## Interfaces offered

- KMIP 1.0, 1.1, 1.2, 1.3, 1.4, 2.0, 2.1, 3.0
- PKCS#11: v2, v3

## Tested versions

- KMIP Query Vendor Identification string: `Cryptsoft KMIP Java Server Version 2.5.1k`.
  - Web UI About panel: `Securosys Key Manager Version 1.1.1`
- PKCS#11 to
[`grimsel.securosys.ch`](https://docs.securosys.com/connectivity-details/developer-program/), an
[X-600](https://www.securosys.com/en/hsm/x-series?hsCtaAttrib=176338626588#technical-specifications) HSM.
  - Securosys PKCS#11 log file says: `Primus API PKCS#11 v2.8.2`
  - C_GetInfo says:
    - cryptokiVersion: `3.2`
    - manufacturerID: `Securosys SA`
    - libraryDescription: `PKCS#11 Library`
    - libraryVersion: `2.82`
  - C_GetTokenInfo says:
    - manufacturerID: `Securorsys SA`
    - model: `Primus HSM`
  - C_GetSlotInfo says:
    - manufacturerID: `Securosys SA`
    - hardwareVersion: `3.4`
    - firmwareVersion: `2.82`

## Known issues

KMIP:
- Does not display the KMIP `Name` attribute via the web UI (_can_ be seen
  using `keyls`).
- Ed448 and Ed25519 via KMIP require KMIP 2.x (per the spec) which we do not
  yet support.
- Ed448 and Ed25519 are currently not possible via KMIP due to a known bug
  on the Securosys KMIP server.

## Testing prerequisites

- Access to the Securosys demo server via KMIP is authenticated using mTLS and
  thus requires that you have the necessary server CA certificate and client
  certificate and client private key files.
- PKCS#11 access is not available to the demo server but with a support
  account the PKCS#11 library and credentials necessary for accessing
  other Securosys HSM servers can be downloaded from the [Securosys Support
  Portal](https://support.securosys.com/).

## Running the KMIP test

- Export environment variables pointing to the mTLS credentials to use:
  - `export SECUROSYS_CA_CERT_PATH=".."`
  - `export SECUROSYS_CLIENT_CERT_PATH=".."`
  - `export SECUROSYS_CLIENT_PRIVATE_KEY_PATH=".."`
- Run the test: `cargo run --package fulltest -- securosys /tmp/report`

## Running the PKCS#11 test

- Export environment ariables pointing to the mTLS credentials to use:
  - `export SECUROSYS_PKCS11_USERNAME=..`
  - `export SECUROSYS_PKCS11_HOST=grimsel.securosys.ch`
  - `export SECUROSYS_PKCS11_PORT=2410`
- Run the test: `cargo run --package fulltest -- securosys-pkcs11 /tmp/report`

## How Securosys CloudHSM works

Securosys CloudHSM does not support KMIP natively but rather is able to be
run with a separate KMIP server product that connects to the actual HSM.

## How the test works

The KMIP test will:
- Execute KMIP operations against the Securosys CloudHSM demo server directly.

The PKCS#11 test will:
- Create a temporary directory.
- Write a Securosys PKCS#11 module configuration file in $TMPDIR that
  configures the host, port and slot to connect to and the username to
  authenticate as, and configures the module to log to a file under $TMPDIR.
- Set the `SECUROSYS_PKCS11_CONF` environment variable to the location of the
  custom configuration file, thereby guiding the Securosys PKCS#11 module to
  use the test configuration.
- Configure Cascade-HSM-Bridge to load the Securosys PKCS#11 module.
- Execute KMIP operations against Cascade-HSM-Bridge which in turn will
  execute PKCS#11 functions in the loaded Securosys PKCS#11 module which will
  result in HTTPS REST API requests being sent to the running Securosys HSM.

## Diagnosing problems

See the log files for Cascade-HSM-Bridge, PKCS#11 Spy and the Securosys
PKCS#11 module that are written to the report directory.
