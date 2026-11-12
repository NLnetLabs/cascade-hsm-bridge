use cryptoki::object::AttributeType;
use kmip::types::{
    common::AttributeName,
    request::{BatchItem, RequestPayload},
    response::{BatchItem as ResBatchItem, ResponsePayload, ResultReason, ResultStatus},
};

use crate::pkcs11::{
    operations::get_attributes::get_attributes, pool::Pkcs11Connection,
    util::get_cached_handle_for_key,
};

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, String)> {
    let RequestPayload::GetAttributes(Some(unique_identifier), Some(attribute_names)) =
        batch_item.request_payload()
    else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a supported GetAttributes payload".to_string(),
        ));
    };

    #[allow(nonstandard_style)]
    let OBJECT_TYPE: AttributeName = AttributeName("Object Type".to_string());
    #[allow(nonstandard_style)]
    let NAME: AttributeName = AttributeName("Name".to_string());
    #[allow(nonstandard_style)]
    let CRYPTOGRAPHIC_ALGORITHM: AttributeName =
        AttributeName("Cryptographic Algorithm".to_string());
    #[allow(nonstandard_style)]
    let CRYPTOGRAPHIC_LENGTH: AttributeName = AttributeName("Cryptographic Length".to_string());

    if attribute_names.is_empty() {
        return Err((
            ResultReason::FeatureNotSupported,
            "At least one attribute must be specified".to_string(),
        ));
    }

    let mut pkcs11_attrs = vec![];

    for kmip_attr_name in attribute_names {
        if kmip_attr_name == &NAME {
            pkcs11_attrs.push(AttributeType::Label);
        } else if kmip_attr_name == &OBJECT_TYPE {
            pkcs11_attrs.push(AttributeType::Class);
        } else if kmip_attr_name == &CRYPTOGRAPHIC_ALGORITHM {
            pkcs11_attrs.push(AttributeType::KeyType);
        } else if kmip_attr_name == &CRYPTOGRAPHIC_LENGTH {
            pkcs11_attrs.push(AttributeType::ModulusBits);
        } else {
            return Err((
                ResultReason::FeatureNotSupported,
                format!("Unsupported attribute '{}'", kmip_attr_name.0),
            ));
        }
    }

    let key_handle = get_cached_handle_for_key(&pkcs11conn, unique_identifier)
        .map_err(|err| (ResultReason::ItemNotFound, err))?;

    let Some(key_handle) = key_handle else {
        return Err((
            ResultReason::ItemNotFound,
            format!("Key with id {} not found", unique_identifier.0),
        ));
    };

    match get_attributes(&pkcs11conn, key_handle, pkcs11_attrs) {
        Ok(attributes) => Ok(ResBatchItem {
            operation: Some(*batch_item.operation()),
            unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
            result_status: ResultStatus::Success,
            result_reason: None,
            result_message: None,
            payload: Some(ResponsePayload::GetAttributes(
                kmip::types::response::GetAttributesResponsePayload {
                    unique_identifier: unique_identifier.clone(),
                    attributes: Some(attributes),
                },
            )),
            message_extension: None,
        }),
        Err(err) => Err((ResultReason::GeneralFailure, err.to_string())),
    }
}
