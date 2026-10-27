[![Discuss on Discourse](https://img.shields.io/badge/Discourse-NLnet_Labs-orange?logo=Discourse)](https://community.nlnetlabs.nl/c/dns-libraries-tools/12)
[![Mastodon Follow](https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social)](https://social.nlnetlabs.nl/@nlnetlabs)


# A KMIP to PKCS#11 bridge for Cascade

`cascade-hsm-bridge` is a Rust application that accepts [KMIP](https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=39d0c648-0a66-4f46-b343-018dc7d3f19c)
requests, converts them to [PKCS#11](https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=922ef643-1e10-4d65-a5ea-018dc7d3f0a4)
format and executes them against a loaded PKCS#11 library. It was created for
use with the [Cascade](https://cascade.nlnetlabs.nl/) project.

## Documentation

Documentation is available as part of the Cascade project [here](https://cascade.docs.nlnetlabs.nl/projects/cascade-hsm-bridge/).

## Building

See ["Building From Source"](https://cascade.docs.nlnetlabs.nl/en/latest/building.html) in the documentation.

## Use cases

### Intended use case: shielding Cascade against an untrusted PKCS#11 library

The use case for which this application is primarily being developed is to
enable [Cascade](https://github.com/NLnetLabs/cascade/) to make use of a
Hardware Security Module (HSM) via a PKCS#11 interface without having to load
an untrusted 3rd party PKCS#11 library into its process.

This is particularly important for a Rust application as the PKCS#11 interface
exposes the application to code that is likely not protected by the guarantees
provided by the Rust compiler, as the PKCS#11 is a foreign function interface
beyond which the Rust compiler cannot see.

If the PKCS#11 library experiences a fatal error that may not be reason to
exit the parent application, whether or not that is appropriate is highly
dependent on the purpose of that application. Any STDOUT and STDERR output
produced by the PKCS#11 library may also become mixed with output from the
application itself which can be confusing.

### Other use cases

This project could potentially act as the basis for a general purpose KMIP
to PKCS#11 bridge. However, at present and for the foreseeable future we plan
only to implement the tiny fraction of the KMIP specification needed by the
Cascade project, and the only KMIP client that will be tested against will
be Cascade.

## Technical foundations

This application is possible thanks to the following foundational Rust crates on which it builds:

- [cryptoki](https://crates.io/crates/cryptoki)
- [kmip-protocol](https://crates.io/crates/kmip-protocol)
- [rustls](https://crates.io/crates/rustls)
- [tokio](https://crates.io/crates/tokio)

## Testing

In `crates/fulltest` an integration test is provided. It uses:
- a [`domain-kmip`](https://github.com/NLnetLabs/domain-kmip) based client,
- the SoftHSMv2 PKCS#11 module as backing HSM to be loaded by
  Cascade-HSM-Bridge.
- the [`ring`](https://crates.io/crates/ring) library to verify the generated
  signatures.

To run the test (requires SoftHSMv2 to be installed) do:

```sh
cargo test --package fulltest
```

The test creates signing keys using different algorithms and verifies
that using Cascade-HSM-Bridge to sign with them yields valid signatures.
