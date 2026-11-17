# Integration test

## What is this?

This crate contains an integration test of Cascade-HSM-Bridge backed by the
SoftHSMv2 PKCS#11 module and using the `domain-kmip` crate to interact with
the bridge.

As the test uses Cascade-HSM-Bridge which can load any PKCS#11 module the
test also supports additional PKCS#11 HSM modules from various providers other
than the SoftHSMv2 default. The support includes generation of the appropriate
config file and capture of any available logging from the module.

And as the test uses a KMIP client it also supports additional KMIP compatible
HSMs sending requests direct to the HSM rather than to Cascade-HSM-Bridge.

## Pre-requisites

To run this test you will need to have the appropriate PKCS#11 module
installed and any dependencies it has, and/or have the necessary credentials
to use the chosen PKCS#11 module or KMIP compatbile HSM.

## Running the test

Note: Running the test will also cause the Cascade-HSM-Test code to be
recompiled.

Running the test like so will test by default against SoftHSMv2:

```
cargo test --package fulltest
```

## Testing against other HSMs

To test against a HSM other than SoftHSMv2, consult the help to determine
which HSMs are supported:

```
cargo test --package --fulltest -- --help 
```

## Diagnosing issues

Set the `RUST_LOG` environment variable to `debug` or `trace` for increased
KMIP client logging, including KMIP messages in hexadecimal form, e.g.:

Provide the `--report-dir` and `--hex-to-txt-bin-path` arguments to cause
the test to capture the Cascade-HSM-Bridge log to a file and automatically
extract the KMIP messages and use [hex-to-txt](https://github.com/NLnetLabs/kmip-protocol/tree/main/examples/hex_to_txt)
to render them in human readable form to a file called `kmip.log` in the
chosen report directory.

Provide the --`pkcs11spy` argument to cause tests of PKCS#11 modules to
load the chosen module via the [OpenSC pkcs11-spy module](https://github.com/OpenSC/OpenSC/wiki/Using-OpenSC#pkcs-11-spy)
to produce a log of the PKCS#11 function calls made by Cascade-HSM-Bridge
and the results of those calls.

## Why does this test not live directly in the Cascade-HSM-Bridge crate?

This crate is separate to the Cascade-HSM-Bridge crate because both crates
use the `kmip-protocol` crate dependency but with different features.

The bridge uses `kmip-protocol` directly with the async
`tls-with-tokio-rustls` feature enabled. The integration test uses
`kmip-protocol` indirectly via `domain-kmip` which uses the `kmip-protocol`
crate with the non-async `tls-with-rustls` feature enabled.

When both dependencies are present in the same crate, cargo feature
unification causes both the sync and async features to be enabled at once
which will cause compilation failures in `kmip-protocol` due to its use of
`maybe_async`: it expects to be compiled for async use or non-async use
and cannot be compiled for both at once.
