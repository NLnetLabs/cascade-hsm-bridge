# Nitrokey NetHSM

## About

[NetHSM](https://www.nitrokey.com/products/nethsm) is a physical HSM product
from vendor Nitrokey. The software powering the hardware is also [available as
a Docker image](https://docs.nitrokey.com/nethsm/container/).

## Interfaces offered

- PKCS#11 v2 and v3.

## Tested versions

- Docker image nitrokey/nethsm@sha256:5c0d8fc85a2a0d32343504bf5fe37f45b62129011a2ac05e6a5221a6c9f523f6.
  NetHSM container logs report `Starting NetHSM S-Keyfender - version 5.1 (2482cca)`.
- PKCS#11 module `nethsm-pkcs11-v3.0.1-x86_64-linux-glibc.so`.
- Cascade-HSM-Bridge reports `Loaded Nitrokey PKCS#11 library v3.0 supporting Cryptoki v3.2: Nitrokey NetHsm PKCS#11 library`.

## Known issues

- No support for Ed448. Manifests as PKCS#11 error `InvalidAttribute(384)`.
  NetHSM container logs report `WARN  nethsm_pkcs11::backend::key] Unsupported EC key type OID 1.3.101.113`.

## Testing prerequisites

- The NetHSM Docker image must already be running. Run it with command:
  `docker run --rm -ti -p 127.0.0.1:8443:8443 docker.io/nitrokey/nethsm:testing`.
- Install the NetHSM PKCS#11 module (see the NetHSM documentation [here](https://docs.nitrokey.com/nethsm/pkcs11-setup)).
- [OPTIONAL] Set environment variable `NETHSM_HOST` to
  `<IP ADDRESS>:<PORT NUMBER>` of the running NetHSM instance, if not the
  default (`127.0.0.1:8443`).
- [OPTIONAL] Set environment variable `NETHSM_PKCS11_PATH` to the location of
  the NetHSM PKCS#11 module `.so` file if the test is not able to find it.

Note: While Nitrokey offer a [public testing instance](https://docs.nitrokey.com/nethsm/integration#demo-instance)
changes in order to use it.

## Running the test

- Start the NetHSM instance if needed: `docker run --name nethsm --rm nethsm/testing`.
- Run the test: `cargo run --package fulltest -- nethsm`
- Inspect the NetHSM logs if needed: `docker logs nethsm`
- Stop the NetHSM instance (Docker will remove it): `docker stop nethsm`

## How NetHSM works

The NetHSM PKCS#11 module communicates via HTTPS with the REST API of a
running NetHSM instance.

The NetHSM software must be provisioned before first use. The test takes care
of this, assuming that the NetHSM instance is not yet provisioned.

The NetHSM PKCS#11 module ignores PKCS#11 PIN authentication, instead using
authentication details specified in the PKCS#11 module configuration file to
authenticate REST API requests. From the
[NetHSM PKCS#11 documentation](https://docs.nitrokey.com/nethsm/pkcs11-setup#users):

> The operator and administrator users are both optional but the module won’t
> start if no user is configured. This is so you can configure the module with
> only an administrator user, only an operator user or both at the same time.
> 
> When the two users are set the module will use the operator by default and
> only use the administrator user when the action needs it.
> 
> The regular PKCS#11 user is mapped to the NetHSM operator and the PKCS#11 SO
> is mapped to the NetHSM administrator.

## How the test works

The test will:
- Create a temporary directory.
- Write a NetHSM PKCS#11 module configuration file in $TMPDIR that configures
  a known PKCS#11 label, defines the operator and administrator username and
  password to authenticate to the NetHSM REST API with, and sets the URL of
  the NetHSM REST API to communicate with.
- Wait until a successful TLS connection can be made to the NetHSM REST API.
- Use the NetHSM REST API to determine if the HSM is already provisioned or
  not. If needed provisions the HSM with admin and operator users.
- Set the `P11NETHSM_CONFIG_FILE` environment variable to the location of the
  custom configuration file, thereby guiding the NetHSM PKCS#11 module to use
  the test configuration.
- Configure Cascade-HSM-Bridge to load the NetHSM PKCS#11 module.
- Execute KMIP operations against Cascade-HSM-Bridge which in turn will
  execute PKCS#11 functions in the loaded NetHSM PKCS#11 module which will
  result in HTTPS REST API requests being sent to the running NetHSM instance.

## Diagnosing problems

The test does not capture the log output of the running NetHSM. If connecting
to a locally running Docker instance you can use the `docker logs` command
to inspect the NetHSMs own logs if needed.
