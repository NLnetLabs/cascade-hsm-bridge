use kmip::types::response::{BatchItem as ResBatchItem, ResultReason, ResultStatus};

pub fn mk_err_batch_item(reason: ResultReason, message: String) -> ResBatchItem {
    ResBatchItem {
        operation: None,
        unique_batch_item_id: None,
        result_status: ResultStatus::OperationFailed,
        result_reason: Some(reason),
        result_message: Some(message),
        payload: None,
        message_extension: None,
    }
}
