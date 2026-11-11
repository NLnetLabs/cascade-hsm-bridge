use std::{
    collections::HashMap,
    ffi::OsStr,
    io::{self, ErrorKind},
    net::SocketAddr,
    option::Option,
    path::PathBuf,
    process::Command,
    time::Duration,
};

use command_group::{CommandGroup, GroupChild};
use domain_kmip::dep::kmip_protocol::{
    self,
    net::{ConnectionSettings, NetError, TlsClientAuth, TlsServerAuth},
};
use rcgen::{CertifiedKey, generate_simple_self_signed};
use tempfile::TempDir;

use crate::common::hsms::{Hsm, Hsms};

pub struct Pykmip {
    env_vars: HashMap<&'static str, String>,

    process: GroupChild,

    log_path: PathBuf,

    tls_cert: rcgen::Certificate,

    tls_private_key: rcgen::KeyPair,
}

impl Pykmip {
    pub fn launch(tempdir: &TempDir) -> io::Result<Hsms> {
        let hsm_config_path = tempdir.path().join("pykmip.conf");
        let tls_cert_path = tempdir.path().join("cert.pem");
        let tls_key_path = tempdir.path().join("key.pem");
        let db_path = tempdir.path().join("pykmip.db");
        let log_path = tempdir.path().join("pykmip.log");
        let run_server_path = tempdir.path().join("run-server.sh");
        let run_server_py_path = tempdir.path().join("run-server.py");
        let python_venv_path = tempdir.path().join(".venv");
        let python_constraints_path = tempdir.path().join("pykmip.constraints");

        // Generate a self-signed certificate and key for PyKMIP to use.
        let CertifiedKey {
            cert: tls_cert,
            signing_key: tls_private_key,
        } = generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .map_err(|err| io::Error::other(format!("generate_simple_self_signed: {err}")))?;

        std::fs::write(&tls_cert_path, tls_cert.pem())
            .map_err(|err| io::Error::other(format!("cert.pem(): {err}")))?;
        std::fs::write(&tls_key_path, tls_private_key.serialize_pem())
            .map_err(|err| io::Error::other(format!("signing_key.serialize_pem(): {err}")))?;

        let tls_cert_path_str = tls_cert_path.to_string_lossy();
        let tls_key_path_str = tls_key_path.to_string_lossy();
        let db_path_str = db_path.to_string_lossy();
        let log_path_str = log_path.to_string_lossy();

        std::fs::write(
            &hsm_config_path,
            format!(
                r#"
[server]
hostname=127.0.0.1
port=5696
certificate_path={tls_cert_path_str}
key_path={tls_key_path_str}
ca_path={tls_cert_path_str}
auth_suite=TLS1.2
enable_tls_client_auth=False
tls_cipher_suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
logging_level=DEBUG
database_path={db_path_str}
"#
            ),
        )?;

        let hsm_config_path_str = hsm_config_path.to_string_lossy();

        std::fs::write(
            &run_server_py_path,
            format!(
                r#"
from kmip.services.server import KmipServer

server = KmipServer(
    config_path='{hsm_config_path_str}',
    log_path='{log_path_str}'
)

with server:
    server.serve()
"#
            ),
        )?;

        std::fs::write(
            &python_constraints_path,
            format!(
                r#"
SQLAlchemy<2
"#
            ),
        )?;

        let run_server_py_path_str = run_server_py_path.to_string_lossy();
        let python_venv_path_str = python_venv_path.to_string_lossy();
        let python_constraints_path_str = python_constraints_path.to_string_lossy();

        std::fs::write(
            &run_server_path,
            format!(
                r#"
virtualenv -p python3.11 {python_venv_path_str}
source {python_venv_path_str}/bin/activate
pip install --upgrade pip
pip install pykmip --constraint {python_constraints_path_str}
# pip install git+https://github.com/dellock6/pykmip-veeam.git
python {run_server_py_path_str}
"#
            ),
        )?;

        let process = Command::new("/usr/bin/bash")
            .args(["-e", &run_server_path.to_string_lossy()])
            .current_dir(tempdir.path())
            .group_spawn()?;

        // Wait for PyKMIP to become ready.
        let conn_settings = ConnectionSettings {
            host: "127.0.0.1".to_string(),
            port: 5696,
            username: None,
            password: None,
            tls_client_auth: Some(TlsClientAuth {
                cert_bytes: tls_cert.pem().into_bytes(),
                private_key_bytes: tls_private_key.serialize_pem().into_bytes(),
            }),
            tls_server_auth: TlsServerAuth::None,
            tls_server_name: None,
            connect_timeout: Some(Duration::from_secs(10)),
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            max_response_bytes: None,
        };

        for _ in 0..5 {
            match kmip_protocol::net::tls::rustls::connect(&conn_settings) {
                Ok(_) => { /* Nothing to dp */ }
                Err(NetError::IoError(err)) if err.kind() == ErrorKind::ConnectionRefused => {
                    // Retry
                    std::thread::sleep(Duration::from_secs(1));
                    println!("Retrying..");
                }
                Err(other_err) => {
                    return Err(io::Error::other(format!("connect: {other_err}")));
                }
            }
        }

        println!("PyKMIP is up");

        let env_vars = HashMap::new();
        Ok(Hsms::Pykmip(Self {
            env_vars,
            process,
            log_path,
            tls_cert,
            tls_private_key,
        }))
    }
}

impl Drop for Pykmip {
    fn drop(&mut self) {
        println!("Stopping PyKMIP");
        // Stop PyKMIP.
        let _ = self.process.kill();

        if std::thread::panicking() {
            // Try to provide the pykmip log file.
            if let Ok(log) = std::fs::read_to_string(&self.log_path) {
                println!("pykmip log:\n{log}");
            }
        }
    }
}

impl Hsm for Pykmip {
    fn lib_path(&self) -> Option<&OsStr> {
        None
    }

    fn env_vars(&self) -> &HashMap<&'static str, String> {
        &self.env_vars
    }

    fn username(&self) -> Option<&str> {
        None
    }

    fn password(&self) -> Option<&str> {
        None
    }

    fn address(&self) -> Option<SocketAddr> {
        Some(SocketAddr::from(([127, 0, 0, 1], 5696)))
    }

    fn tls_client_auth(&self) -> Option<TlsClientAuth> {
        Some(TlsClientAuth {
            cert_bytes: self.tls_cert.pem().into_bytes(),
            private_key_bytes: self.tls_private_key.serialize_pem().into_bytes(),
        })
    }

    fn tls_server_auth(&self) -> TlsServerAuth {
        TlsServerAuth::None
    }

    fn tls_server_name(&self) -> Option<String> {
        None
    }
}
