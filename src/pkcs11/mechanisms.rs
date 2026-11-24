/// Query the availabile PKCS#11 mechanisms (cryptographic algorithms).
use cryptoki::{
    context::Pkcs11,
    mechanism::{MechanismInfo, MechanismType},
    slot::Slot,
};

const MECHANISM_TYPES: [MechanismType; 3] = [
    MechanismType::RSA_PKCS_KEY_PAIR_GEN,
    MechanismType::ECC_KEY_PAIR_GEN,
    MechanismType::ECC_EDWARDS_KEY_PAIR_GEN,
];

/// Information about the set of available PKCS#11 mechanisms (cryptographic
/// algorithms).
#[derive(Copy, Clone, Debug)]
pub struct AvailableMechanisms {
    mech_infos: [Option<MechanismInfo>; 3],
}

impl AvailableMechanisms {
    /// Query and store details about available PKCS#11 mechanisms of
    /// interest.
    pub fn new(pkcs11: &Pkcs11, slot: Slot) -> Self {
        let mut mech_infos = [None; 3];

        for (i, mech_type) in MECHANISM_TYPES.iter().enumerate() {
            if let Ok(mech_info) = pkcs11.get_mechanism_info(slot, *mech_type) {
                mech_infos[i] = Some(mech_info);
            }
        }

        Self { mech_infos }
    }

    /// Iterate over the set of wanted PKCS#11 mechainsms.
    pub fn keys(&self) -> std::slice::Iter<'_, MechanismType> {
        MECHANISM_TYPES.iter()
    }

    /// Get information about a PKCS#11 mechanism, if available.
    pub fn get(&self, mech_type: &MechanismType) -> Option<MechanismInfo> {
        MECHANISM_TYPES
            .iter()
            .position(|v| v == mech_type)
            .and_then(|idx| self.mech_infos[idx])
    }
}
