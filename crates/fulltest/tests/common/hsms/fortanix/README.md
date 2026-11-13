# Fortanix Data Security Manager

## About

The [Fortanix DSM](https://support.fortanix.com/docs/fortanix-dsm-saas-overview)
is:

> An integrated Data Security as a Service that provides secure key management
> and cryptography services including cloud key management, secret management,
> and tokenization to protect sensitive data in public, private, hybrid, or
> multi-cloud environments. Encryption keys are stored in the FIPS 140-2 Level
> 3 certified HSM and cryptographic operations are securely executed within
> the module. HSM as a service simplifies operations and reduces management
> overhead. The service can be accessed publicly using the cloud.

Fortanix offer a demo instance at:

- KMIP: eu.smartkey.io:5696
- Web UI: https://eu.smartkey.io

## Interfaces offered

- KMIP 1.x
- PKCS#11 v2 and v3

## Tested versions

- KMIP Query Vendor Identification string `Fortanix`.
- Web UI version: 5.10.2985

## Known issues

- ECDSAP256SHA256 and ECDSAP384SHA384 via KMIP are not currently working due
  to error `FeatureNotSupported: Don't have handling for attribute Cryptographic Parameters`.
- Ed448 and Ed25519 via KMIP require KMIP 2.x (per the spec) which Fortanix
  DSM does not yet support.
- Ed25519 is supported via PKCS#11, but Ed448 fails with an unrecognised
  elliptic curve OID.
- PKCS#11 support requires a patched Rust Cryptoki library version. See:
  https://github.com/parallaxsecond/rust-cryptoki/issues/374

## Testing prerequisites

- Access to the Fortanix Free Trial server at https://eu.smartkey.io/.
- An 'App' must have been created via the Fortanix DSM web UI.
- KMIP access to the Securosys demo server is authenticated using the
  username and password associated with the created 'App' and can be
  retrieved from the web UI.
- PKCS#11 access to the Securosys demo server is authenticated using the
  API key associated with the created 'App' and can be retrieved from the web
  UI.

## Running the KMIP test

- Export environment variables specifying the username and password to use:
  - `export FORTANIX_USER=".."`
  - `export FORTANIX_PASS=".."`
- Run the test: `cargo run --package fulltest -- fortanixdsm`

## Running the PKCS#11 test

- Export an environment variable specifying the API key to use:
  - `export FORTANIX_API_KEY=".."`
- Run the test: `cargo run --package fulltest -- fortanixdsm-pkcs11`

## How Fortanix DSM works

TODO

## How the test works

The test will:
- Execute KMIP operations against the Fortanix DSM demo server directly.
