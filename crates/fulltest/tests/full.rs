//! Test the full path between KMIP clients and PKCS#11 HSM.
//!
//! This is a full-system test: it initializes `cascade-hsm-bridge` with
//! [SoftHSMv2] and queries it from a KMIP client. The full breadth of
//! supported KMIP operations is tested.
//!
//! [SoftHSMv2]: https://github.com/softhsm/SoftHSMv2
//!
//! # Process
//!
//! A single `cascade-hsm-bridge` server is initialized using [SoftHSMv2]. It
//! is configured to store all filesystem state in a temporary directory, so
//! that distinct invocations do not affect each other. Multiple tests are
//! executed against that server. If any of them fail, they can be run in
//! isolation.

// Only available on Unix machines.
#![cfg(unix)]

mod common;

use std::{sync::Arc, time::Duration};

use clap::Parser;
use domain_kmip::dep::domain::crypto::{
    openssl,
    sign::{GenerateParams, SignRaw},
};
use domain_kmip::dep::kmip_protocol::net::{ConnectionSettings, sync_pool::ConnPool};
use domain_kmip::dep::kmip_protocol::types::request::RequestPayload;
use domain_kmip::dep::kmip_protocol::types::response::ResponsePayload;
use io_redirect::redirect_std_to_path;
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

use common::daemon::Daemon;
use common::hsms::*;

use crate::common::{args::Args, util::extract_human_readable_kmip_messages};

//------------ main ----------------------------------------------------------

fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    let args = Args::parse().process_report_dir();

    // Allocate a temporary directory for the daemon.
    let temp_dir = tempfile::tempdir().unwrap_or_else(|err| {
        eprintln!("Could not create a temporary directory: {err}");
        std::process::exit(1);
    });

    let mut kmip_client_log = None;

    if let Some(report_dir) = args.report_dir() {
        if report_dir.exists() {
            eprintln!(
                "Could not create report directory '{}': Directory already exists",
                report_dir.display()
            );
            std::process::exit(1);
        }
        std::fs::create_dir_all(report_dir).unwrap();

        println!(
            "Report will be generated in: {}",
            report_dir.canonicalize().unwrap().display()
        );

        let test_log_path = report_dir.join("test.log");
        println!("Redirecting stdout/stderr to {}", test_log_path.display());
        redirect_std_to_path(&test_log_path, false).unwrap();

        let kmip_client_log_path = report_dir.join("client.log");
        let file_logger = tracing_appender::rolling::never(
            kmip_client_log_path.parent().unwrap(),
            kmip_client_log_path.file_name().unwrap(),
        );
        kmip_client_log = Some(kmip_client_log_path);

        tracing_subscriber::fmt()
            .with_max_level(LevelFilter::TRACE)
            .with_writer(file_logger)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .init();
    }

    // Remember to update the value_parser array in common/args.rs when the
    // list of strings to match here changes.
    let hsm = match args.hsm() {
        "fortanixdsm" => FortanixDSM::launch(&temp_dir, &args, false).unwrap(),
        "fortanixdsm-pkcs11" => FortanixDSM::launch(&temp_dir, &args, true).unwrap(),
        "kryoptic" => Kryoptic::launch(&temp_dir).unwrap(),
        "nethsm" => Nethsm::launch(&temp_dir).unwrap(),
        "pykmip" => Pykmip::launch(&temp_dir, &args).unwrap(),
        "securosys" => Securosys::launch(&temp_dir, &args, false).unwrap(),
        "securosys-pkcs11" => Securosys::launch(&temp_dir, &args, true).unwrap(),
        "softhsm2" => Softhsm2::launch(&temp_dir).unwrap(),
        "thales" => ThalesDPOD::launch(&temp_dir).unwrap(),
        "yubihsm2" => Yubihsm2::launch(&temp_dir, &args).unwrap(),
        _ => unreachable!(),
    };

    // Configure OpenSC pksc11-spy if needed.
    let hsm = hsm.pkcs11spyify(&temp_dir, &args).unwrap();

    // If the HSM is a PKCS#11 module launch Cascade-HSM-Bridge to serve
    // access to it via the KMIP interface.
    let (daemon, conn_settings) = if hsm.lib_path().is_some() {
        println!("HSM lib path: {:?}", hsm.lib_path());
        let daemon =
            Daemon::launch(&temp_dir, &args, hsm.current_dir(), &hsm).unwrap_or_else(|err| {
                eprintln!("Could not launch the daemon: {err}");
                std::process::exit(1);
            });

        let conn_settings = ConnectionSettings {
            host: daemon.address().ip().to_string(),
            port: daemon.address().port(),
            username: hsm.username().map(ToString::to_string),
            password: hsm.password().map(ToString::to_string),
            connect_timeout: Some(Duration::from_secs(5)),
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            max_response_bytes: Some(4096),
            tls_client_auth: daemon.tls_client_auth(),
            tls_server_auth: daemon.tls_server_auth(),
            tls_server_name: daemon.tls_server_name(),
        };

        (Some(daemon), conn_settings)
    } else {
        // The HSM is a KMIP HSM, no bridge needed.
        let conn_settings = ConnectionSettings {
            host: hsm.address().unwrap().ip().to_string(),
            port: hsm.address().unwrap().port(),
            username: hsm.username().map(ToString::to_string),
            password: hsm.password().map(ToString::to_string),
            connect_timeout: Some(Duration::from_secs(5)),
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            max_response_bytes: Some(4096),
            tls_client_auth: hsm.tls_client_auth(),
            tls_server_auth: hsm.tls_server_auth(),
            tls_server_name: hsm.tls_server_name(),
        };

        (None, conn_settings)
    };

    // Establish a connection pool for talking to the HSM.
    let conn_pool = ConnPool::new(
        format!("{hsm}"),
        Arc::new(conn_settings),
        32,
        Some(Duration::from_secs(5)),
        Some(Duration::from_secs(5)),
    )
    .unwrap();

    // Query the protocol versions supported by the KMIP server.
    let request = RequestPayload::DiscoverVersions(vec![]);
    let mut client = conn_pool.get().unwrap();
    let response = client.do_request_payload(request).unwrap();
    let response = TryInto::<ResponsePayload>::try_into(response).unwrap();
    if let ResponsePayload::DiscoverVersions(payload) = response {
        if let Some(versions) = payload.supported_versions {
            println!(
                "KMIP server supports versions: {}",
                versions
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
        }
    }

    // Test each algorithm / size combination of interest.
    let algs_to_test = [
        GenerateParams::RsaSha256 { bits: 1024 },
        GenerateParams::RsaSha256 { bits: 2048 },
        GenerateParams::RsaSha512 { bits: 1024 },
        GenerateParams::RsaSha512 { bits: 2048 },
        GenerateParams::EcdsaP256Sha256,
        GenerateParams::EcdsaP384Sha384,
        GenerateParams::Ed448,
        GenerateParams::Ed25519,
    ];

    let mut failing_algs = vec![];
    for alg in &algs_to_test {
        if !test_keygen_signing(&conn_pool, alg.clone()) {
            failing_algs.push(alg.algorithm().to_mnemonic_str().unwrap());
        }
    }

    // If there is no Cascade-HSM-Bridge instance, post-process the client log
    // instead to create a human readable KMIP message log.
    if daemon.is_none() {
        if let Some(kmip_client_log) = kmip_client_log {
            if let Some(report_dir) = args.report_dir() {
                extract_human_readable_kmip_messages(
                    &kmip_client_log,
                    args.hex_to_txt_bin_path().map(|p| p.as_path()),
                    report_dir,
                );
            }
        }
    }

    // Panic if any of the tests failed.
    if !failing_algs.is_empty() {
        let failing_algs_csv = failing_algs.join(", ");
        panic!(
            "{}/{} algorithms failed: {failing_algs_csv}",
            failing_algs.len(),
            algs_to_test.len()
        );
    }
}

/// Test that key generation and signing works.
///
/// A new key will be generated (using the given parameters) and used for
/// signing. The public key will be retrieved and used to locally verify the
/// signature.
fn test_keygen_signing(pool: &ConnPool, key_params: GenerateParams) -> bool {
    print!("test_keygen_signing({:?})...", key_params);
    if let Err(err) = do_test_keygen_signing(pool, key_params) {
        println!("err: {err}");
        false
    } else {
        println!("ok");
        true
    }
}

fn do_test_keygen_signing(pool: &ConnPool, key_params: GenerateParams) -> Result<(), String> {
    let algorithm = key_params.algorithm();

    // Generate a new key. Note that the labels are NOT the IDs of the
    // generated key parts, those are returned by generate().
    let pub_label = format!("public-key-label-alg-{}", key_params.algorithm());
    let pri_label = format!("private-key-label-alg-{}", key_params.algorithm());
    let key = domain_kmip::generate(pub_label, pri_label, key_params, 0, pool.clone())
        .map_err(|err| format!("generate: {err}"))?;

    // Retrieve the public key, for local use.
    let dnskey = key.dnskey();
    let pubkey =
        openssl::PublicKey::from_dnskey(&dnskey).map_err(|err| format!("from_dnskey: {err}"))?;

    // Sign data with this key.
    let data = b"Hello World!";
    let sig = key
        .sign_raw(data)
        .map_err(|err| format!("sign_raw: {err}"))?;

    // Verify the signature.
    assert_eq!(algorithm, sig.algorithm());
    pubkey
        .verify(data, sig.as_ref())
        .map_err(|err| format!("verify: {err}"))?;

    // PyKMIP says the object isn't activated so cannot be revoked.
    domain_kmip::destroy(key.public_key_id(), pool.clone())
        .map_err(|err| format!("destroy pub: {err}"))?;
    domain_kmip::destroy(key.private_key_id(), pool.clone())
        .map_err(|err| format!("destroy pri: {err}"))?;

    Ok(())
}
