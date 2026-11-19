# Thales Luna Cloud HSM via DOpD

## About

[Thales Data Protection on Demand (DPoD)](https://cpl.thalesgroup.com/encryption/data-protection-on-demand) is:

> a cloud‑based platform providing a wide range of cloud HSM and key
> management services through a simple online marketplace. Deploy and manage
> key management and hardware security module services, on‑demand and from
> the cloud.

[Luna Cloud HSM](https://cpl.thalesgroup.com/encryption/data-protection-on-demand/services/luna-cloud-hsm)
is a cloud HSM service available through DPoD:

> The Luna Cloud HSM service is a generic key vault that can be used for a
> wide variety of use cases.

## Interfaces offered

- PKCS#11: v2, v3

## Tested versions

- Cascade-HSM-Bridge reports `SafeNet PKCS#11 library v10.9 supporting Cryptoki v2.20: Chrystoki`
- `lunacm` reports:
  - Model: `Cryptovisor 7`
  - Firmware Version: `7.3.0`
  - CV Firmware Version: `2.0.5`
  - Plugin Version: `Clodu 2.7.0-1110`

## Known issues

- None.

## Testing prerequisites

To test with a Luna Cloud HSM via Thales DPoD you will need a compatible
operating system or Docker. These instructions assume you are using Docker.

Then:

- Signup for a trial account at https://market.dpondemand.io/signup
- Go to `Services` -> `Add Service` -> `Luna Cloud HSM`.
- Tick `Remove FIPS restrictons`.
- Go to `Services` -> `MyServices` -> your-service-name -> `Service Clients` -> `Create Service Client`
- Download the `Service Client` zip.
- Follow the [Linux minimal client access](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/install/client_install/linux_minimal_client_access_dpod.htm) instructions.

You should now have a Docker container running that contains the necessary
PKCS#11 module, configuration and credentials to use your free trial Luna
Cloud HSM.

Before it can be used it must be setup:

- `apt update`
- `apt install -y git curl vim build-essential pkg-config libssl-dev`
- `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal -y`
- `. ~/.cargo/env`
- `git clone https://github.com/NLnetLabs/cascade-hsm-bridge.git`
- `cd cascade-hsm-bridge`
- `cargo test -p fulltest -- thales`

## Running the test

`cargo run --package fulltest -- thales`

## How Thales DOpD works

Thales Data Protection on Demand offers access to various services, of
which the Luna Cloud HSM is one.

Access to the service is via PKCS#11 module zip downloaded from the DPoD
portal pre-configured for the service you provisioned. While the zip contents
can be used as-is, Thales guides advise using it in an Ubuntu 20.04 container.
Therefore the Cascade-HSM-Bridge integration test must be run from inside that
container.

The HSM is pre-provisioned with a partition but crypto officer and security
officer passwords need to be set on first use. This must be done using the
`lunacm` tool which is included in the zip archive.

## How the test works

The test will:
- Create a temporary directory.
- Write a `lunacm` script to a file in $TMPDIR that configures access passwords
  in the HSM.
- Invoke `lunacm` passing it the script we created.
- Configure Cascade-HSM-Bridge to load the Thales PKCS#11 module.
- Execute KMIP operations against Cascade-HSM-Bridge which in turn will
  execute PKCS#11 functions in the loaded Thales PKCS#11 module which will
  issue commands to the Luna Cloud HSM instance.
