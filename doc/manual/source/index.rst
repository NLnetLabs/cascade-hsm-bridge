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
communicte using the different industry standard protocols `KMIP
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

+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| KMIP Operation                                                                                           | PKCS#11 Function                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Limitations                                                         |
+==========================================================================================================+=========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================+=====================================================================+
| `Activate <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613546>`_         | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Returns with success as PKCS#11 has no notion of object activation. |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Create Key Pair <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613529>`_  | `C_GenerateKeyPair <https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc235002392>`_                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Only supports RSA and ECDSA at present.                             |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| Discover Versions                                                                                        | N/A                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Get <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613538>`_              | `C_FindObjectsInit <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002352>`_, `C_FindObjects <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002353>`_, `C_FindObjectsFinal <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002354>`_ & `C_GetAttributeValue <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002350>`_                                                                                                                                                                                              |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Modify Attribute <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613542>`_ | C_SetAttributeValue                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Query <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613552>`_            | C_GetSlotInfo, C_GetTokenInfo                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| `Sign <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613558>`_             | `C_FindObjectsInit <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002352>`_, `C_FindObjects <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002353>`_, `C_FindObjectsFinal <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002354>`_, `C_SignInit <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002372>`_, `C_Sign <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc235002373>`_ & `C_SignFinal <https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc2350023753>`_ |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+
| N/A                                                                                                      | C_GetFunctionList, C_GetInfo, C_Initialize                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |                                                                     |
+----------------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------------------------------------------------------------------+

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
