# Integration test

## What is this?

This crate contains an integration test of Cascade-HSM-Bridge backed by the
SoftHSMv2 PKCS#11 module and using the `domain-kmip` crate to interact with
the bridge.

## Pre-requisites

To run this test you will need to have SoftHSMv2 installed.

## Running the test

Note: Running the test will also cause the Cascade-HSM-Test code to be
recompiled.

Running the test can be done from within the crate directory like so:

```
cargo test
```

Alternatively it can be run from the root Cascade-HSM-Bridge directory:

```
cargo test --package fulltest
```

## Diagnosing issues

This crate supports the RUST_LOG environment variable for increasing the
level at which the client side of the KMIP communication is logged. Set
RUST_LOG=trace for maximum logging, including KMIP requests and responses
logged in hexadecimal form.

E.g.

```
2026-10-07T12:38:08.668519Z TRACE kmip_protocol::net::client: Writing 584 bytes to the server: 4200780100000240420...
```

To interpret those responses, copy the 4200... byte sequence to a file,
then use the `kmip-protocol` crate `hex_to_txt` example tool to print it
in more readable form, e.g.

```
cd src/kmip-protocol
cargo run --example hex_to_txt -- /path/to/file/containing/hex/bytes.txt
...
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/examples/hex_to_txt -`
Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
  Tag: Response Header (0x42007A), Type: Structure (0x01), Data:
    Tag: Protocol Version (0x420069), Type: Structure (0x01), Data:
...
```

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
