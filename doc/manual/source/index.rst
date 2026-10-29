A KMIP to PKCS#11 Bridge
========================

.. only:: html

   |lastupdated| |mastodon|

   .. |lastupdated| image:: https://img.shields.io/github/last-commit/NLnetLabs/cascade-hsm-bridge?path=%2Fdoc%2Fmanual&label=last%20updated
      :alt: Last docs update
      :target: https://github.com/NLnetLabs/cascade-hsm-bridge/commits/main/doc/manual/source

   .. |mastodon| image:: https://img.shields.io/mastodon/follow/114692612288811644?domain=social.nlnetlabs.nl&style=social
      :alt: Mastodon
      :target: https://social.nlnetlabs.nl/@nlnetlabs

This application provides a bridge between HSM clients and servers that
communicate using the different industry standard protocols `KMIP
<https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=39d0c648-0a66-4f46-b343-018dc7d3f19c>`_
and `PKCS#11
<https://groups.oasis-open.org/communities/tc-community-home2?CommunityKey=922ef643-1e10-4d65-a5ea-018dc7d3f0a4>`_.

KMIP is a network protocol that describes how to send messages to a HSM via
a TLS encrypted TCP connection.

PKCS#11 is a 'C' language API (Application Programming Interface) that allows
a program to be written to communicate with a loaded PKCS#11 library which
PKSC#11 compatible HSM vendors supply to their customers.

Received KMIP requests are converted into PKCS#11 instructions
and then executed against a loaded PKCS#11 library.

Generated PKCS#11 responses are converted into KMIP responses and sent back to
the client over the TCP+TLS network connection.

It was primarily
created to serve `Cascade <https://www.nlnetlabs.nl/projects/cascade/>`_.

Installing or building
----------------------

For instructions on installing Cascade-HSM-Bridge, or building it from
sources, please see the `Cascade documentation
<https://cascade.docs.nlnetlabs.nl/en/latest/installation.html>`_.

Use Cases
---------

Shielding Cascade against an untrusted PKCS#11 library
""""""""""""""""""""""""""""""""""""""""""""""""""""""

The use case for which this application is primarily being developed is to
enable `Cascade <https://cascade.docs.nlnetlabs.nl/en/latest/installation.html>`_
to make use of a Hardware Security Module (HSM) via a PKCS#11 interface
without having to load an untrusted 3rd party PKCS#11 library into its
process.

This is particularly important for a `Rust <https://rust-lang.org/>`_
application such as Cascade as the PKCS#11 interface exposes the application
to code that is likely not protected by the guarantees provided by the Rust
compiler, as the PKCS#11 is a foreign function interface beyond which the Rust
compiler cannot see.

If the PKCS#11 library experiences a fatal error that may not be reason to exit
the parent application, whether that is appropriate is highly dependent
on the purpose of that application. Any STDOUT and STDERR output produced by
the PKCS#11 library may also become mixed with output from the application
itself which can be confusing.

General Purpose KMIP <-> PKCS#11 Bridge (not supported)
"""""""""""""""""""""""""""""""""""""""""""""""""""""""

This project could potentially act as the basis for a general purpose KMIP
to PKCS#11 bridge. However, at present and for the foreseeable future we plan
only to implement the tiny fraction of the KMIP specifications needed by the
Cascade project, and the only KMIP client that will be tested against will
be Cascade.

Technical foundations
"""""""""""""""""""""

This application is possible thanks to the following foundational Rust crates
on which it builds:

- `cryptoki <https://crates.io/crates/cryptoki>`_
- `kmip-protocol <https://crates.io/crates/kmip-protocol>`_
- `rustls <https://crates.io/crates/rustls>`_
- `tokio <https://crates.io/crates/tokio>`_

Supported protocols
-------------------

This application currently only supports a subset of `KMIP 1.2 <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html>`_
via the TCP+TLS+TTLV transport. There is no support for the HTTPS+XML or
HTTPS+JSON transports defined by the KMIP profiles specification.

The loaded PKCS#11 module should conform to the `PKCS#11 v2.40 <https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html>`_
specification.

.. note:: Ed448 and Ed25519 require a `PKCS#11 v3.0 <https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cos01/pkcs11-curr-v3.0-cos01.html>`_ compatible HSM.

Supported operations
--------------------

+----------------------+----------------------------------------------------------------------------------------------------------+
| KMIP Operation       | Maps To PKCS#11 Function(s)                                                                              |
+======================+==========================================================================================================+
| `Activate`_          | `C_FindObjectsInit`_, `C_FindObjects`_ & `C_FindObjectsFinal`_ [1]_                                      |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Create Key Pair`_   | `C_GenerateKeyPair`_                                                                                     |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Destroy`_           | `C_FindObjectsInit`_, `C_FindObjects`_, `C_FindObjectsFinal`_ & `C_DestroyObject`_                       |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Discover Versions`_ | N/A                                                                                                      |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Get`_               | `C_FindObjectsInit`_, `C_FindObjects`_, `C_FindObjectsFinal`_ & `C_GetAttributeValue`_                   |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Modify Attribute`_  | `C_FindObjectsInit`_, `C_FindObjects`_, `C_FindObjectsFinal`_ & `C_SetAttributeValue`_                   |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Query`_             | `C_GetSlotInfo`_, `C_GetTokenInfo`_                                                                      |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Revoke`_            | `C_FindObjectsInit`_, `C_FindObjects`_ & `C_FindObjectsFinal`_ [1]_                                      |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Sign`_              | `C_FindObjectsInit`_, `C_FindObjects`_, `C_FindObjectsFinal`_, `C_SignInit`_, `C_Sign`_ & `C_SignFinal`_ |
+----------------------+----------------------------------------------------------------------------------------------------------+

.. [1] The `Activate` and `Revoke` KMIP operations have no equivalent in
       PKCS#11. These operations thus only check that the key exists.

.. _Activate: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613546
.. _Create Key Pair: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613529
.. _Destroy: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613548
.. _Discover Versions: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613553
.. _Get: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613538
.. _Modify Attribute: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613542
.. _Query: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613552
.. _Revoke: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613547
.. _Sign: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
.. _C_DestroyObject: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024123
.. _C_FindObjectsInit: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323610889
.. _C_FindObjects: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323205461
.. _C_FindObjectsFinal: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc385057926
.. _C_GenerateKeyPair: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc235002392
.. _C_GetAttributeValue: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024125
.. _C_GetSlotInfo: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024106
.. _C_GetTokenInfo: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024107
.. _C_SetAttributeValue: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024126
.. _C_SignInit: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024143
.. _C_Sign: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024144
.. _C_SignFinal: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024146

Supported Algorithms
--------------------

+------------------------------------+----------------------------+-------------------------------------+-----------------------------------------------------------------------------------------+
| KMIP `CryptographicAlgorithm`      | KMIP `CryptographicLength` | PKCS#11 Mechanism                   | PKCS#11 Additional Key Attributes                                                       |
+====================================+============================+=====================================+=========================================================================================+
| `CryptographicAlgorithm`_::RSA     | Used as the modulus.       | `CKM_RSA_PKCS_KEY_PAIR_GEN`_        | `CKA_LABEL`_, `CKA_KEY_TYPE`_: `CKK_RSA`_, `CKA_PUBLIC_EXPONENT`_,  `CKA_MODULUS_BITS`_ |
+------------------------------------+----------------------------+-------------------------------------+-----------------------------------------------------------------------------------------+
| `CryptographicAlgorithm`_::ECDSA   | Used to select the curve.  | `CKM_EC_KEY_PAIR_GEN`_              | `CKA_LABEL`_, `CKA_KEY_TYPE`_: `CKK_EC`_                                                |
+------------------------------------+----------------------------+-------------------------------------+-----------------------------------------------------------------------------------------+
| `CryptographicAlgorithm`_::Ed448   | N/A                        | `CKM_EC_EDWARDS_KEY_PAIR_GEN`_ [2]_ | `CKA_LABEL`_, `CKA_KEY_TYPE`_: `CKK_EC_EDWARDS`_, `CKA_EC_PARAMS`_                      |
+------------------------------------+----------------------------+-------------------------------------+-----------------------------------------------------------------------------------------+
| `CryptographicAlgorithm`_::Ed25519 | N/A                        | `CKM_EC_EDWARDS_KEY_PAIR_GEN`_ [2]_ | `CKA_LABEL`_, `CKA_KEY_TYPE`_: `CKK_EC_EDWARDS`_, `CKA_EC_PARAMS`_                      |
+------------------------------------+----------------------------+-------------------------------------+-----------------------------------------------------------------------------------------+

.. [2] `CMK_EC_EDWARDS_KEY_PAIR_GEN` is only available for HSM supporting the
       PKCS#11 v3.0 specification. The `CKA_EC_PARAMS`_ select the elliptic
       curve to be used via :rfc:8410 OID, either id-Ed448 or id-Ed25519.

.. _CryptographicAlgorithm: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613485
.. _CKA_EC_PARAMS: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cos01/pkcs11-curr-v3.0-cos01.html#_Toc30061182
.. _CKA_KEY_TYPE: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959717
.. _CKA_LABEL: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959705
.. _CKA_MODULUS_BITS: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226889
.. _CKA_PUBLIC_EXPONENT: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959720
.. _CKK_RSA: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226888
.. _CKK_EC: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226931
.. _CKK_EC_EDWARDS: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cos01/pkcs11-curr-v3.0-cos01.html#_Toc30061182
.. _CKM_EC_KEY_PAIR_GEN: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cos01/pkcs11-curr-v3.0-cos01.html#_Toc30061186
.. _CKM_EC_EDWARDS_KEY_PAIR_GEN: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v3.0/cos01/pkcs11-curr-v3.0-cos01.html#_Toc30061187
.. _CKM_RSA_PKCS_KEY_PAIR_GEN: https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cos01/pkcs11-curr-v2.40-cos01.html#_Toc408226891

Key Attributes
--------------

Keys are created with the following PKCS#11 attributes:

+------------------------------+-------------------------------+
| Public Key                   | Private Key                   |
+==============================+===============================+
| `CKA_CLASS`_: CKO_PUBLIC_KEY | `CKA_CLASS`_: CKO_PRIVATE_KEY |
+------------------------------+-------------------------------+
| `CKA_ID`_: [3]_              | `CKA_ID`_: [3]_               |
+------------------------------+-------------------------------+
| `CKA_VERIFY`_: CK_TRUE       | `CKA_SIGN`_: CKA_TRUE         |
+------------------------------+-------------------------------+
| `CKA_ENCRYPT`_: CK_FALSE     | `CKA_DECRYPT`_: CKA_FALSE     |
+------------------------------+-------------------------------+
| `CKA_TOKEN`_: CK_TRUE        | `CKA_TOKEN`_: CKA_TRUE        |
+------------------------------+-------------------------------+
| `CKA_WRAP`_: CK_FALSE        | `CKA_PRIVATE`_: CKA_TRUE      |
+------------------------------+-------------------------------+
|                              | `CKA_SENSITIVE`_: CKA_TRUE    |
+------------------------------+-------------------------------+

.. [3] See :ref:`key-id-mapping`.
.. _CKA_CLASS: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959698
.. _CKA_DECRYPT: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
.. _CKA_ENCRYPT: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959718
.. _CKA_ID: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959717
.. _CKA_PRIVATE: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959705
.. _CKA_SENSITIVE: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
.. _CKA_SIGN: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959719
.. _CKA_TOKEN: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959705
.. _CKA_VERIFY: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959718
.. _CKA_WRAP: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959718

.. _key-id-mapping:

Key ID Mapping
--------------

In PKCS#11 a public and private key pair can both be identified by the same
CKA_ID but different object class.

KMIP treats the public and private key pairs as separate objects which must
each have their own unique identifier.

When a Generate Key Pair request is received the Name attributes will be used
as CKA_LABEL values for the generated keys and a random 20 byte CKA_ID will be
generated. (20 bytes because the CKA_ID field was originally intended to X.509
Key Identifier values which :rfc:5280 defines as being 160 bits long i.e.
20 bytes).

On successful key pair generation the CKA_ID will be used to construct KMIP
compatible Unique Identifiers to return to the client, by appending `_priv`
to the hexadecimal form of the CKA_ID to construct the private key ID, and by
appending `_pub` to the hexadecimal form of the CKA_ID to construct the public
key ID.

Other requests that take a KMIP unique identifier as input will strip and use
the `_priv` or `_pub` suffix to know whether the request targets the private or
public key respectively.

Object Handle Caching
---------------------

As can be noted from the table above, many operations require finding the
PKCS#11 object before it can be acted upon. This is because the PKCS#11
functions that need to be invoked to do the actual work take an object handle
as input, not a `CKA_ID`. To avoid having to keep going back to the PKCS#11
library to determine the object handle for a given CKA_ID, Cascade-HSM-Bridge
caches the `CKA_ID` to object handle mappings in memory.


.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Getting Started
   :name: toc-getting-started

   usage

.. toctree::
   :maxdepth: 2
   :hidden:
   :caption: Manual Pages
   :name: toc-manual-pages

   man/cascade-hsm-bridge
   man/cascade-hsm-bridge-config.toml
