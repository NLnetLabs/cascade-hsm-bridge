use core::net::SocketAddr;
use std::io::ErrorKind;

use cascade_hsm_bridge_cfg::v1::Config;

use cryptoki::object::ObjectHandle;
use cryptoki::types::AuthPin;
use daemonbase::error::{ExitError, Failed};
use kmip::types::common::Operation;
use kmip::types::request::RequestMessage;
use kmip::types::response::{BatchItem, ResultReason};
use moka::sync::Cache;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};

use crate::kmip::operations::{
    activate, create_key_pair, destroy, discover_versions, get, modify_attribute, query, revoke,
    sign, unknown,
};
use crate::kmip::util::mk_err_batch_item;
use crate::pkcs11::util::Pkcs11Pools;

pub type HandleCache = Cache<String, ObjectHandle>;

pub async fn handle_client_requests(
    stream: TlsStream<TcpStream>,
    peer_addr: SocketAddr,
    mut config: Config,
    mut pkcs11_pools: Pkcs11Pools,
) -> Result<(), ExitError> {
    // Note: We don't call ServerBuilder::with_credentials() because we
    // don't know the credentials used by the loaded PKCS#11 module, we just
    // pass the received KMIP credentials on to the PKCS#11 module for
    // verification.
    let mut server = kmip::net::ServerBuilder::new(stream).build();

    loop {
        let batch = match server.receive_request().await {
            Ok(req) if !is_supported_protocol_version(&req) => {
                // https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html#_Toc409613599
                let msg = "Only KMIP protocol version <= 1.2 are supported".to_string();
                vec![mk_err_batch_item(ResultReason::GeneralFailure, msg)]
            }

            Ok(req) => {
                let (res, c, p) = tokio::task::spawn_blocking(move || {
                    let r = process_request(&config, &pkcs11_pools, peer_addr, req);
                    (r, config, pkcs11_pools)
                })
                .await
                .map_err(|_| ExitError::from(Failed))?;

                config = c;
                pkcs11_pools = p;
                res?
            }

            Err(err) => match err {
                kmip::net::NetError::AuthenticationError => {
                    vec![mk_err_batch_item(
                        ResultReason::AuthenticationNotSuccessful,
                        err.to_string(),
                    )]
                }
                kmip::net::NetError::IoError(err) if err.kind() == ErrorKind::UnexpectedEof => {
                    // Client has disconnected.
                    debug!("Client disconnected: {err}");
                    return Ok(());
                }
                err => {
                    warn!("Error receiving request: {err}");
                    vec![mk_err_batch_item(
                        ResultReason::GeneralFailure,
                        err.to_string(),
                    )]
                }
            },
        };

        if let Err(err) = server.send_response_batch(batch).await {
            warn!("Failed to send response to client {peer_addr}: {err}");
        }
    }
}

fn process_request(
    config: &Config,
    pkcs11_pools: &Pkcs11Pools,
    peer_addr: SocketAddr,
    req: RequestMessage,
) -> Result<Vec<BatchItem>, ExitError> {
    let authentication = req.header().authentication();

    let Some(slot_label_id_or_index) = authentication.and_then(|auth| auth.username()) else {
        return Ok(vec![mk_err_batch_item(
            ResultReason::GeneralFailure,
            "Requests must be authenticated with a username (PKCS#11 slot label/id/index)"
                .to_string(),
        )]);
    };

    let Some(pin) = authentication.and_then(|auth| auth.password()) else {
        return Ok(vec![mk_err_batch_item(
            ResultReason::GeneralFailure,
            "Requests must be authenticated with a password (PKCS#11 pin)".to_string(),
        )]);
    };

    let pool = match pkcs11_pools.get(slot_label_id_or_index) {
        Ok(pool) => pool,
        Err(err) => {
            return Ok(vec![mk_err_batch_item(
                ResultReason::AuthenticationNotSuccessful,
                format!("No PKCS#11 slot found: {err}",),
            )]);
        }
    };

    let mut res_batch_items = vec![];

    let tid = std::thread::current();
    info!(
        "Processing batch of {} items from peer {peer_addr} on thread {tid:?}",
        req.batch_items().len()
    );

    for batch_item in req.batch_items() {
        debug!(
            "Processing batch item operation {} from client {peer_addr}",
            batch_item.operation()
        );

        let start = std::time::Instant::now();

        // Note: we are NOT compliant with the KMIP 1.2 Baseline Server profile
        // [1] because we lack support for the following KMIP operations:
        //   - Locate
        //   - Check
        //   - Get Attributes
        //   - Add Attribute
        //   - Modify Attribute
        //   - Delete Attribute
        // [1]: https://docs.oasis-open.org/kmip/profiles/v1.2/os/kmip-profiles-v1.2-os.html#_Toc409613184
        let res = match batch_item.operation() {
            Operation::Query => query::op(&pool, config, batch_item),
            _ => {
                let pkcs11conn = pool.get().unwrap();
                if let Err(err) =
                    pkcs11conn.ensure_logged_in(AuthPin::new(pin.to_string().into_boxed_str()))
                {
                    Err((ResultReason::AuthenticationNotSuccessful, err.to_string()))
                } else {
                    match batch_item.operation() {
                        Operation::Activate => activate::op(pkcs11conn, batch_item),
                        Operation::CreateKeyPair => create_key_pair::op(pkcs11conn, batch_item),
                        Operation::Destroy => destroy::op(pkcs11conn, batch_item),
                        Operation::DiscoverVersions => discover_versions::op(batch_item),
                        Operation::Get => get::op(pkcs11conn, batch_item),
                        Operation::ModifyAttribute => modify_attribute::op(pkcs11conn, batch_item),
                        Operation::Sign => sign::op(pkcs11conn, batch_item),
                        Operation::Revoke => revoke::op(pkcs11conn, batch_item),
                        _ => unknown::op(batch_item),
                    }
                }
            }
        };

        debug!(
            "Processed batch item operation {} from client {peer_addr} in {}us: {}",
            batch_item.operation(),
            start.elapsed().as_micros(),
            if res.is_ok() { "Succeeded" } else { "Failed" },
        );

        let res_batch_item = match res {
            Ok(res_batch_item) => res_batch_item,
            Err((reason, message)) => mk_err_batch_item(reason, message),
        };

        res_batch_items.push(res_batch_item);
    }

    Ok(res_batch_items)
}

fn is_supported_protocol_version(req: &RequestMessage) -> bool {
    let ver = req.header().protocol_version();
    let major_ver = ver.0.0;
    let minor_ver = ver.1.0;
    major_ver == 1 && minor_ver <= 2
}
