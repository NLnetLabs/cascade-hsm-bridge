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

This application currently only supports a subset of KMIP 1.2 via the
TCP+TLS+TTLV transport. There is no support for the HTTPS+XML or HTTPS+JSON
transports defined by the KMIP profiles specification.

The loaded PKCS#11 module should conform to the PKCS#11 v2.40 specification.

Supported operations
--------------------

+----------------------+----------------------------------------------------------------------------------------------------------+
| KMIP Operation       | Maps To PKCS#11 Function(s)                                                                              |
+======================+==========================================================================================================+
| `Activate`_          | N/A                                                                                                      |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Create Key Pair`_   | `C_GenerateKeyPair`_                                                                                     |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Discover Versions`_ | N/A                                                                                                      |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Get`_               | `C_FindObjectsInit`_, `C_FindObjects`_, `C_FindObjectsFinal`_ & `C_GetAttributeValue`_                   |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Modify Attribute`_  | `C_SetAttributeValue`_                                                                                   |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Query`_             | `C_GetSlotInfo`_, `C_GetTokenInfo`_                                                                      |
+----------------------+----------------------------------------------------------------------------------------------------------+
| `Sign`_              | `C_FindObjectsInit`_, `C_FindObjects`_, `C_FindObjectsFinal`_, `C_SignInit`_, `C_Sign`_ & `C_SignFinal`_ |
+----------------------+----------------------------------------------------------------------------------------------------------+

.. _Activate: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613546
.. _Create Key Pair: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613529
.. _Discover Versions: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613553
.. _Get: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613538
.. _Modify Attribute: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613542
.. _Query: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613552
.. _Sign: https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558
.. _C_FindObjectsInit: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323610889
.. _C_FindObjects: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323205461
.. _C_FindObjectsFinal: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc385057926
.. _C_GenerateKeyPair: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc235002392
.. _C_GetAttributeValue: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024125
.. _C_GetSlotInfo: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024106
.. _C_GetTokenInfo: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024107
.. _C_SetAttributeValue: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024126
.. _C_SignInit: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024143
.. _C_Sign: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024144
.. _C_SignFinal: _https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#Toc323024146

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
