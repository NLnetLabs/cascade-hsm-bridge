use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use kmip::types::common::UniqueIdentifier;
use tracing::debug;

use crate::pkcs11::error::Error;
use crate::pkcs11::pool::Pkcs11Connection;
use crate::pkcs11::util::pkcs11_cka_id_to_kmip_unique_identifier;

pub fn find_objects(
    pkcs11conn: Pkcs11Connection,
    private: bool,
) -> Result<Vec<UniqueIdentifier>, Error> {
    let mut ids = vec![];

    let template = if private {
        [Attribute::Class(ObjectClass::PRIVATE_KEY)]
    } else {
        [Attribute::Class(ObjectClass::PUBLIC_KEY)]
    };

    for key_handle in pkcs11conn.session().find_objects(&template)? {
        let mut attrs = pkcs11conn
            .session()
            .get_attributes(key_handle, &[AttributeType::Id])?;

        let Some(Attribute::Id(cka_id)) = attrs.pop() else {
            debug!("C_GetAttributeValue failed: key handle {key_handle} not found");
            return Err(Error::not_found("Key", "ObjectHandle", key_handle));
        };

        ids.push(pkcs11_cka_id_to_kmip_unique_identifier(&cka_id, private));
    }

    Ok(ids)
}
