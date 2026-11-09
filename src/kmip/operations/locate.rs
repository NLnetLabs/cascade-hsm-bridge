use kmip::types::{
    common::{AttributeName, AttributeValue, ObjectType},
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, LocateResponsePayload, ResponsePayload, ResultReason,
        ResultStatus,
    },
};

use crate::pkcs11::{operations::find_objects::find_objects, pool::Pkcs11Connection};

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, String)> {
    let RequestPayload::Locate(kmip_attrs) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Locate payload".to_string(),
        ));
    };

    #[allow(nonstandard_style)]
    let OBJECT_TYPE: AttributeName = AttributeName("Object Type".to_string());

    if kmip_attrs.is_empty() {
        return Err((
            ResultReason::FeatureNotSupported,
            "A single search attribute must be specified".to_string(),
        ));
    }

    if kmip_attrs.len() > 1 {
        return Err((
            ResultReason::FeatureNotSupported,
            "Only a single search attribute, either ObjectType::PrivateKey or ObjectType::PublicKey, is supported".to_string(),
        ));
    }

    let private = if kmip_attrs[0].name() == &OBJECT_TYPE {
        match kmip_attrs[0].value() {
            AttributeValue::ObjectType(ObjectType::PrivateKey) => true,
            AttributeValue::ObjectType(ObjectType::PublicKey) => false,
            _ => {
                return Err((
                    ResultReason::FeatureNotSupported,
                    "Only ObjectType::PrivateKey or ObjectType::PublicKey are supported"
                        .to_string(),
                ));
            }
        }
    } else {
        return Err((
            ResultReason::FeatureNotSupported,
            "Only ObjectType::PrivateKey or ObjectType::PublicKey are supported".to_string(),
        ));
    };

    match find_objects(pkcs11conn, private) {
        Ok(unique_identifiers) => Ok(ResBatchItem {
            operation: Some(*batch_item.operation()),
            unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
            result_status: ResultStatus::Success,
            result_reason: None,
            result_message: None,
            payload: Some(ResponsePayload::Locate(LocateResponsePayload {
                unique_identifiers,
            })),
            message_extension: None,
        }),
        Err(err) => Err((ResultReason::GeneralFailure, err.to_string())),
    }
}
