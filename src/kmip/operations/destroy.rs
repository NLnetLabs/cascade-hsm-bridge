use kmip::types::{
    request::{BatchItem, RequestPayload},
    response::{
        BatchItem as ResBatchItem, DestroyResponsePayload, ResponsePayload, ResultReason,
        ResultStatus,
    },
};

use crate::pkcs11::pool::Pkcs11Connection;
use crate::pkcs11::util::get_cached_handle_for_key;

pub fn op(
    pkcs11conn: Pkcs11Connection,
    batch_item: &BatchItem,
) -> Result<ResBatchItem, (ResultReason, String)> {
    let RequestPayload::Destroy(Some(id)) = batch_item.request_payload() else {
        return Err((
            ResultReason::InvalidMessage,
            "Batch item payload is not a Destroy payload".to_string(),
        ));
    };

    // Make sure the key exists
    match get_cached_handle_for_key(&pkcs11conn, id)
        .map_err(|err| (ResultReason::ItemNotFound, err))?
    {
        Some(object_handle) => {
            pkcs11conn
                .session()
                .destroy_object(object_handle)
                .map_err(|err| {
                    (
                        ResultReason::GeneralFailure,
                        format!("Failed to destroy object handle {object_handle}: {err}"),
                    )
                })?;
            // Nothing more to do as PKCS#11 doesn't support revocaton.
            Ok(ResBatchItem {
                operation: Some(*batch_item.operation()),
                unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
                result_status: ResultStatus::Success,
                result_reason: None,
                result_message: None,
                payload: Some(ResponsePayload::Revoke(DestroyResponsePayload {
                    unique_identifier: id.clone(),
                })),
                message_extension: None,
            })
        }

        None => Ok(ResBatchItem {
            operation: Some(*batch_item.operation()),
            unique_batch_item_id: batch_item.unique_batch_item_id().cloned(),
            result_status: ResultStatus::OperationFailed,
            result_reason: Some(ResultReason::ItemNotFound),
            result_message: None,
            payload: None,
            message_extension: None,
        }),
    }
}
