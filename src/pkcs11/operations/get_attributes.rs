use std::ops::{Deref, DerefMut};

use bcder::decode::IntoSource;
use bcder::{OctetString, Oid, PrintableString};
use cryptoki::mechanism::MechanismType;
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use domain::utils::base16;
use kmip::types::common::{
    AttributeName, AttributeValue, CryptographicAlgorithm, NameType, NameValue, ObjectType,
};
use kmip::types::request::Name;
use tracing::debug;

use crate::pkcs11::error::Error;
use crate::pkcs11::operations::get::{ED448_OID, ED25519_OID, SECP256R1_OID};
use crate::pkcs11::pool::Pkcs11Connection;

pub fn get_attributes(
    pkcs11conn: &Pkcs11Connection,
    key_handle: ObjectHandle,
    mut request_attrs: Vec<AttributeType>,
) -> Result<Vec<kmip::types::response::Attribute>, Error> {
    let mut kmip_attrs = AttributeVec::new();
    let mut is_edwards = false;

    // If the caller wants to know the Key Type we can't determine that for
    // Ed25519 and Ed448 keys without knowing the EC Point attribute value
    // too, so add that into the set of attributes that we want to know from
    // the PKCS#11 module.
    if request_attrs.contains(&AttributeType::KeyType) {
        request_attrs.push(AttributeType::EcPoint);
        request_attrs.push(AttributeType::EcParams);
    }

    let attrs = loop {
        let res = pkcs11conn
            .session()
            .get_attributes(key_handle, &request_attrs);

        if matches!(res, Err(cryptoki::error::Error::NotSupported))
            && request_attrs.contains(&AttributeType::KeyGenMechanism)
        {
            // Retry without KeyGenMechanism attribute, as at least the
            // Nitrokey NetHSM doesn't support it and we can also get the
            // information we need from the KeyType attribute.
            debug!("C_GetAttributeValue failed, re-trying without CKA_KEY_GEN_MECHANISM");
            request_attrs.retain(|p| p != &AttributeType::KeyGenMechanism);
            continue;
        }

        let attrs = res?;

        if attrs.is_empty() {
            debug!("C_GetAttributeValue failed: key handle {key_handle} not found");
            return Err(Error::not_found("Key", "ObjectHandle", key_handle));
        } else {
            debug!("C_GetAttributeValue: key handle={key_handle}, attributes: {attrs:?}");
            break attrs;
        }
    };

    // https://docs.oasis-open.org/kmip/ug/v1.2/cn01/kmip-ug-v1.2-cn01.html#_Toc407027125
    //   "“Raw” key format is intended to be applied to symmetric keys and not
    //    asymmetric keys"
    //
    // As we deal in assymetric keys (RSA, ECDSA), not symmetric keys, we
    // should not use KeyFormatType::Raw. However, Fortanix DSM returns
    // KeyFormatType::Raw when fetching key data for an ECDSA public key.

    // NOTE: When generating DNSKEY RDATA OpenDNSSEC queries the modulus and
    // public exponent and trims leading zeros from their bytes by shifting
    // the bytes left and truncating the length. It does this to conform to
    // https://datatracker.ietf.org/doc/html/rfc3110#section-2. The
    // application implementing RFC 3110, i.e. Cascade, should do that, not
    // us.
    debug!("Returned PKCS#11 attributes: {attrs:?}");

    // Parse the returned attribute data.
    for attr in attrs {
        match attr {
            Attribute::Class(object_class) => {
                if object_class == ObjectClass::PRIVATE_KEY {
                    kmip_attrs.insert(AttributeValue::ObjectType(ObjectType::PrivateKey));
                } else if object_class == ObjectClass::PUBLIC_KEY {
                    kmip_attrs.insert(AttributeValue::ObjectType(ObjectType::PublicKey));
                } else {
                    return Err(Error::unsupported_object_class(object_class));
                }
            }

            Attribute::Label(label) => {
                kmip_attrs.insert(AttributeValue::Name(Name(
                    NameValue(String::from_utf8_lossy(&label).to_string()),
                    NameType::UninterpretedTextString,
                )));
            }

            Attribute::KeyType(key_type) => match key_type {
                KeyType::RSA => kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                    CryptographicAlgorithm::RSA,
                )),
                KeyType::EC => kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                    CryptographicAlgorithm::ECDSA,
                )),
                KeyType::EC_EDWARDS => is_edwards = true,
                _ => {
                    return Err(Error::unsupported_key_type(key_type));
                }
            },

            Attribute::KeyGenMechanism(mechanism_type) => {
                if mechanism_type == MechanismType::RSA_PKCS_KEY_PAIR_GEN {
                    kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                        CryptographicAlgorithm::RSA,
                    ));
                } else if matches!(
                    mechanism_type,
                    MechanismType::ECDSA | MechanismType::ECC_KEY_PAIR_GEN
                ) {
                    // YubiHSM returns ECDSA.
                    // SoftHSMv2 returns CKM_EC_KEY_PAIR_GEN.
                    kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                        CryptographicAlgorithm::ECDSA,
                    ));
                } else if mechanism_type == MechanismType::ECC_EDWARDS_KEY_PAIR_GEN {
                    is_edwards = true;
                } else {
                    return Err(Error::unsupported_mechanism_type(mechanism_type));
                }
            }

            Attribute::ModulusBits(bits) => {
                let v = u64::from(bits);
                kmip_attrs.insert(AttributeValue::CryptographicLength(
                    kmip::types::common::CryptographicLength(i32::try_from(v).unwrap()),
                ));
            }

            Attribute::EcParams(params) => {
                // https://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html
                // Attribute     | Data type  | Meaning
                // --------------+------------+-------------------------------
                // CKA_EC_PARAMS | Byte array | DER-encoding of an ANSI X9.62
                //               |            | Parameters value
                //
                // Where:
                //
                // Parameters ::= CHOICE {
                //   ecParameters   ECParameters,
                //   oId           CURVES.&id({CurveNames}),
                //   implicitlyCA   NULL,
                //   curveName     PrintableString
                // }
                //
                // And https://www.rfc-editor.org/info/rfc3279/#section-2.3.5 says:
                //
                // ECParameters ::= SEQUENCE {
                //   version   ECPVer,          -- version is always 1
                //   fieldID   FieldID,         -- identifies the finite field over
                //                              -- which the curve is defined
                //   curve     Curve,           -- coefficients a and b of the
                //                              -- elliptic curve
                //   base      ECPoint,         -- specifies the base point P
                //                              -- on the elliptic curve
                //   order     INTEGER,         -- the order n of the base point
                //   cofactor  INTEGER OPTIONAL -- The integer h = #E(Fq)/n
                // }
                //
                // A CHOICE is represented as one of the values in the choice,
                // which one is determined by the DER "tag" that preceeds the
                // data bytes. So we have to try taking either ECParameters (a
                // sequence), or an OID, or a curve name.
                let opt_oid = bcder::Mode::Der
                    .decode(params.as_slice(), |cons| {
                        if let Some(ec_parameters) = cons.take_opt_sequence(|_cons| {
                            // The ECParameters SEQUENCE
                            // We don't know how to parse this yet, ignore it
                            // for now.
                            Ok(())
                        })? {
                            // We have ECParameters.
                            debug!("Ignoring ANSI X9.62 ECParameters: {ec_parameters:?}");
                            Ok(None)
                        } else if let Some(oid) = Oid::take_opt_from(cons)? {
                            // We have a curve OID.
                            Ok(Some(oid))
                        } else if let Some(curve_name) = PrintableString::take_opt_from(cons)? {
                            // We have a curve name.
                            // We don't know how to match on curve names yet,
                            // ignore it for now.
                            debug!("Got ANSI X9.62 curve name: {curve_name}");
                            match curve_name.to_string().as_str() {
                                "edwards25519" => Ok(Some(Oid(ED25519_OID.0.into()))),
                                "edwards448" => Ok(Some(Oid(ED448_OID.0.into()))),
                                _ => Ok(None),
                            }
                        } else {
                            // This isn't possible according to the PKCS#11
                            // v2.40 spec.
                            debug!("Ignoring unexpected field in ANSI X9.62 Parameters value");
                            Ok(None)
                        }
                    })
                    .map_err(|err| {
                        Error::MalformedDataReceived(format!(
                            "CKA_EC_PARAM DER decoding error: {err}"
                        ))
                    })?;

                match opt_oid {
                    Some(oid) if oid == SECP256R1_OID => {
                        kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                            kmip::types::common::CryptographicAlgorithm::ECDSA,
                        ));
                    }
                    Some(oid) if oid == ED25519_OID => {
                        kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                            kmip::types::common::CryptographicAlgorithm::Ed25519,
                        ));
                    }
                    Some(oid) if oid == ED448_OID => {
                        kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                            kmip::types::common::CryptographicAlgorithm::Ed448,
                        ));
                    }
                    Some(other_oid) => {
                        debug!("Ignoring unknown OID {other_oid:?}");
                    }
                    None => {
                        // Nothing to do
                    }
                }
            }

            Attribute::EcPoint(octets) => {
                // The KMIP client expects to receive an ASN.1 DER encoded
                // SubjectPublicKeyInfo response like so, but we receive an
                // ASN.1 DER OCTET STRING.
                //
                //   SubjectPublicKeyInfo SEQUENCE @0+89 (constructed): (2 elem)
                //     algorithm AlgorithmIdentifier SEQUENCE @2+19 (constructed): (2 elem)
                //       algorithm OBJECT_IDENTIFIER @4+7: 1.2.840.10045.2.1|ecPublicKey|ANSI X9.62 public key type
                //       parameters ANY OBJECT_IDENTIFIER @13+8: 1.2.840.10045.3.1.7|prime256v1|ANSI X9.62 named elliptic curve
                //     subjectPublicKey BIT_STRING @23+66: (520 bit)
                //
                // From: https://www.rfc-editor.org/rfc/rfc5480.html#section-2.1.1
                //   The parameter for id-ecPublicKey is as follows and MUST always be
                //   present:
                //
                //     ECParameters ::= CHOICE {
                //       namedCurve         OBJECT IDENTIFIER
                //       -- implicitCurve   NULL
                //       -- specifiedCurve  SpecifiedECDomain
                //     }
                //       -- implicitCurve and specifiedCurve MUST NOT be used in PKIX.
                //       -- Details for SpecifiedECDomain can be found in [X9.62].
                //       -- Any future additions to this CHOICE should be coordinated
                //       -- with ANSI X9.
                debug!(
                    "Received {} bytes of EcPoint: {}",
                    octets.len(),
                    base16::encode_display(&octets)
                );

                let inner_bytes = bcder::Mode::Der
                    .decode(octets.into_source(), OctetString::take_from)
                    .map_err(|err| {
                        Error::MalformedDataReceived(format!(
                            "Failed to parse CKA_EC_POINT value as a DER OCTET STRING: {err}"
                        ))
                    })?
                    .into_bytes();

                debug!(
                    "Converted EcPoint to {} bytes (is_edwards={is_edwards}): {}",
                    inner_bytes.len(),
                    base16::encode_display(&inner_bytes)
                );

                if is_edwards {
                    match inner_bytes.len() {
                        32 => {
                            kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                                CryptographicAlgorithm::Ed25519,
                            ));
                        }
                        57 => {
                            kmip_attrs.insert(AttributeValue::CryptographicAlgorithm(
                                CryptographicAlgorithm::Ed448,
                            ));
                        }
                        _ => { /* Unrecognised, ignore */ }
                    }
                }
            }

            _ => {
                // ignore unexpected attributes
            }
        }
    }

    Ok(kmip_attrs.into())
}

fn value_to_attr(value: AttributeValue) -> kmip::types::response::Attribute {
    let name = AttributeName(
        match value {
            AttributeValue::Name(_) => "Name",
            AttributeValue::ObjectType(_) => "Object Type",
            AttributeValue::CryptographicAlgorithm(_) => "Cryptographic Algorithm",
            AttributeValue::CryptographicLength(_) => "Cryptographic Length",
            _ => unimplemented!(),
        }
        .to_string(),
    );

    kmip::types::response::Attribute {
        name,
        index: None,
        value,
    }
}

struct AttributeVec(Vec<kmip::types::response::Attribute>);

impl AttributeVec {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn insert(&mut self, value: AttributeValue) {
        let item = value_to_attr(value);
        if !self.0.contains(&item) {
            self.0.push(item);
        }
    }

    pub fn into(self) -> Vec<kmip::types::response::Attribute> {
        self.0
    }
}

impl Deref for AttributeVec {
    type Target = Vec<kmip::types::response::Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for AttributeVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
