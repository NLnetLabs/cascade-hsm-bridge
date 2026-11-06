# Changelog

<!-- Changelog template (remove empty sections on release of a version)
## Unreleased version

Released yyyy-mm-dd.

### Breaking changes
### New
### Bug fixes
### Other changes
### Documentation improvements
### Known issues
### Acknowledgements
-->

## Release 0.2.0-beta2

Released 2026-11-06.

This is a minor release to update the versions of `domain` and `kmip-protocol`
used to take bug fixes and follow changes in how mTLS settings are passed to
`domain-kmip` by the `fulltest` crate.


## Release 0.2.0-beta1

Released 2026-11-02.

### Breaking changes

- KMIP Response Message > Response Header > Time Stamp is now correctly
  encoded as KMIP type Date-Time (0x09) rather than as Long Integer (0x03).
  The underlying fix is in the updated KMIP wire protocol serializer ([#64]).
  The new response is incompatible with Cascade 0.1.0-beta7 and dnst
  0.2.0-alpha3 and earlier clients as they use the old deserializer which
  expects the wrong KMIP type code in the response.

### New

- Add `--lib-path` and `CASCADE_HSM_BRIDGE_PKCS11_LIB_PATH` support. ([#51] by
  @ximon18)
- Add support for the KMIP Revoke and Destroy operations. ([#64] by @ximon18)
- Additional algorithm support. ([#65] by @ximon18)

### Bug fixes

- Enable clap `wrap_help` feature like Cascade. ([#50] by @ximon18)
- Report that the bridge supports the ModifyAttribute operation. ([#61]
  by @ximon18)
- Re-enable application log output. ([#66] by @ximon18)

### Other changes

- Show the config file path that could not be loaded. ([#52] by @ximon18)
- Update CI to be more complete based on Cascade CI. ([#64] by @ximon18)
- Factor out the `fulltest` integration test to its own sub-crate ([#64] by
  @ximon18)
- Use updated KMIP wire protocol (de)serializers. ([#64] by @ximon18)
- Don't report client disconnection as an error. ([#65] by @ximon18)
- Bump dependencies. ([#69], [#77] and [#78] by @ximon18)

### Documentation improvements

- Add basic CONTRIBUTING.md with links to CoC and LLM policy. ([#53] by
  @ximon18)
- Add SECURITY.md. ([#54] by @ximon18)
- Be more careful with setting version numbers. ([#55] by @ximon18)
- Clarify PKCS#11 authentication. ([#58] by @thgoebel)
- Improve dev experience (bridge). ([#59] by @thgoebel)
- Document object handle caching. ([#64] by @ximon18)
- Document supported algorithms. ([#65] by @ximon18)
- Document used PKCS#11 key attributes. ([#65] by @ximon18)
- Document KMIP extension for Ed448/Ed25519. ([#65] by @ximon18)
- Fix broken RustDoc links. ([#70] by @ximon18)
- Update the intro in the manual. ([#74] by @ximon18)

### Known issues

- This release depends on an unreleased branch of `kmip-protocol`. Building
  Cascade-HSM-Bridge from 0.1.0-beta2 sources will fail once the dependend
  upon `kmip-protocol` branch is merged and deleted. Final production ready
  releases of Cascade-HSM-Bridge will not have this issue.

### Acknowledgements

Thanks to @thgoebel for testing Cascade-HSM-Bridge and providing valuable
feedback!

[#50]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/50
[#51]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/51
[#52]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/52
[#53]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/53
[#54]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/54
[#55]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/55
[#58]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/58
[#59]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/59
[#61]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/61
[#64]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/64
[#65]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/65
[#66]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/66
[#69]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/69
[#70]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/70
[#74]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/74
[#77]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/77
[#78]: https://github.com/NLnetLabs/cascade-hsm-bridge/pull/78


## 0.1.0-beta1

Released 2026-06-04.


## 0.1.0-alpha

Released 2025-10-22.


## 0.1.0-rc1

Released 2025-09-03.
