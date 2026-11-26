# YubiHSM2

## About

[YubiHSM2](https://www.yubico.com/nl/product/yubihsm-2/) is a
[Yubico](https://www.yubicom.com/) USB hardware HSM product.

## Interfaces offered

- PKCS#11 v2.

## Tested versions

- `yubihsm-shell -a get-device-info` reports v2.2.0.
- `yubihsm-shell --version` reports v2.8.0.
- Cascade-HSM-Bridge reports `Loaded Yubico (www.yubico.com) PKCS#11 library v2.80 supporting Cryptoki v3.1: YubiHSM PKCS#11 Library`.

## Known issues

- Only supports 2048, 3072 and 4096-bit RSA keys so does not support 1024-bit
  keys that Cascade does support.
- Does not support Ed448.
- Ed25519 should be supported but produces error `FeatureNotSupported: Don't have handling for attribute Cryptographic Parameters`.

## Testing prerequisites

- Plug the YubiHSM2 into a free USB socket.
- Install the [YubiHSM2 SDK](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-tools-downloads.html).
- Run the YubiHSM2 Connector (see the [Connector setup docs](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-quick-start.html#hsm2-connect-yubihsm-label).
  and the [PKCS#11 setup docs](https://developers.yubico.com/yubihsm-shell/yubihsm-pkcs11.html)).
- [OPTIONAL] Set environment variable `YUBIHSM_PKCS11_MODULE` to the location of
  `yubihsm_pkcs11.so` if the test is not able to find it.

## Running the test

cargo run --package fulltest -- yubihsm2

## How the YubiHSM2 works

The YubiHSM2 PKCS#11 module communicates via HTTP with a running instance of
the YubiHSM2 Connector application which in turn communicates with a locally
connected YubiHSM2 USB HSM.

Note: It is possible to connect directly to the YubiHSM2 via the `libyubihsm`
but this test connects via the YubiHSM2 Connector.

## How the test works

The test will:
- Create a temporary directory.
- Write a YubiHSM2 PKCS#11 module configuration file in $TMPDIR that directs
  the PKCS#11 module to connect to the YubiHSM2 Connector running at
  http://127.0.0.1:1234/.
- Set the `YUBIHSM_PKCS11_CONF` environment variable to the location of the
  custom configuration file, thereby guiding the YubiHSM2 PKCS#11 module to
  use the test configuration.
- Configure Cascade-HSM-Bridge to load the YubiHSM2 PKCS#11 module.
- Execute KMIP operations against Cascade-HSM-Bridge which in turn will
  execute PKCS#11 functions in the loaded YubiHSM2 PKCS#11 module.
