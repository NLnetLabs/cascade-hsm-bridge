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

- KMIP 1.x and 2.x
- PKCS#11.

## Tested versions

- KMIP Query Vendor Identification string `Cryptsoft KMIP Java Server Version 2.5.1k`.
- Web UI About panel: Securosys Key Manager Version 1.1.1

## Known issues

- Does not display the KMIP `Name` attribute via the web UI (_can_ be seen
  using `keyls`).
- Ed448 and Ed25519 via KMIP require KMIP 2.x (per the spec) which we do not
  yet support.
- Ed448 and Ed25519 are currently not possible via KMIP due to a known bug
  on the Securosys KMIP server.
- PKCS#11 access has not been tested as to [download it](https://docs.securosys.com/pkcs/downloads/)
  credentials for logging in to the Securosys Support portal are required.

## Testing prerequisites

- Access to the Securosys demo server is authenticated using mTLS and thus
  requires that you have the necessary server CA certificate and client
  certificate and client private key files.

## Running the test

- Export environment variables pointing to the mTLS credentials to use:
  - `export SECUROSYS_CA_CERT_PATH=".."`
  - `export SECUROSYS_CLIENT_CERT_PATH=".."`
  - `export SECUROSYS_CLIENT_PRIVATE_KEY_PATH=".."`
- Run the test: `cargo run --package fulltest -- securosys`

## How Securosys CloudHSM works

Securosys CloudHSM is a JCE (Java Cryptography Engine) based HSM and
Securosys offer a separate KMIP Server which acts as a proxy to the
actual HSM.

Access to the KMIP server is secured with mTLS.

## How the test works

The test will:
- Execute KMIP operations against the Securosys CloudHSM demo server directly.
