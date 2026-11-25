//! Handling of quirks exhibited by some HSMs.
use cryptoki::slot::TokenInfo;
use kmip::types::common::CryptographicAlgorithm;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum HsmType {
    ThalesSafeNetLuna,
    Other,
}

/// Detection of and adaptation to known HSM quirks.
///
/// Quirks are unexpected behaviours, e.g. deviation from specification.
#[derive(Copy, Clone, Debug)]
pub struct Quirks {
    hsm_type: HsmType,
}

impl Quirks {
    pub fn new(token_info: &TokenInfo) -> Self {
        let hsm_type = if token_info.manufacturer_id().contains("SafeNet") {
            HsmType::ThalesSafeNetLuna
        } else {
            HsmType::Other
        };

        Self { hsm_type }
    }

    pub fn map_curve_oid(&self, alg: CryptographicAlgorithm, curve_oid: Vec<u8>) -> Vec<u8> {
        match (self.hsm_type, alg) {
            (HsmType::ThalesSafeNetLuna, CryptographicAlgorithm::Ed25519) => {
                // Thales/SafeNet Luna uses a non-standard OID for Ed25519
                // that appears to come from libgcrypt:
                //   1.3.6.1.4.1.11591.15.1
                // See: https://www.thalesdocs.com/dpod/services/luna_cloud_hsm/extern/client_guides/Content/sdk/using/ecc_curve_cross-reference.htm
                // See: https://www.gnupg.org/oids.html
                vec![
                    0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01,
                ]
            }

            _ => curve_oid,
        }
    }
}
