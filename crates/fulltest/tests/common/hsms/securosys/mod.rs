use std::{
    collections::HashMap,
    ffi::OsStr,
    io::{self},
    net::{SocketAddr, ToSocketAddrs},
    option::Option,
    path::PathBuf,
    str::FromStr,
};

use domain_kmip::dep::kmip_protocol::net::{TlsClientAuth, TlsServerAuth};

use crate::common::hsms::{Hsm, Hsms};

pub struct Securosys {
    env_vars: HashMap<&'static str, String>,
    tls_ca_cert: Vec<u8>,
    tls_client_cert: Vec<u8>,
    tls_client_key: Vec<u8>,
}

impl Securosys {
    pub fn launch() -> io::Result<Hsms> {
        let tls_ca_cert_path = std::env::var("SECUROSYS_CA_CERT_PATH")
            .expect("env var 'SECUROSYS_CA_CERT_PATH' should be set");
        let tls_client_cert_path = std::env::var("SECUROSYS_CLIENT_CERT_PATH")
            .expect("env var 'SECUROSYS_CLIENT_CERT_PATH' should be set");
        let tls_client_key_path = std::env::var("SECUROSYS_CLIENT_KEY_PATH")
            .expect("env var 'SECUROSYS_CLIENT_KEY_PATH' should be set");
        let tls_ca_cert_path = PathBuf::from_str(&tls_ca_cert_path).unwrap();
        let tls_client_cert_path = PathBuf::from_str(&tls_client_cert_path).unwrap();
        let tls_client_key_path = PathBuf::from_str(&tls_client_key_path).unwrap();

        let env_vars = HashMap::new();
        Ok(Hsms::Securosys(Self {
            env_vars,
            tls_ca_cert: std::fs::read(tls_ca_cert_path).unwrap(),
            tls_client_cert: std::fs::read(tls_client_cert_path).unwrap(),
            tls_client_key: std::fs::read(tls_client_key_path).unwrap(),
        }))
    }
}

impl Hsm for Securosys {
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
        "kmip-server.cloudshsm.com:5696"
            .to_socket_addrs()
            .unwrap()
            .next()
    }

    fn tls_client_auth(&self) -> Option<TlsClientAuth> {
        Some(TlsClientAuth {
            cert_bytes: self.tls_client_cert.clone(),
            private_key_bytes: self.tls_client_key.clone(),
        })
    }

    fn tls_server_auth(&self) -> TlsServerAuth {
        TlsServerAuth::TrustCertificateAuthority(self.tls_ca_cert.clone())
    }

    fn tls_server_name(&self) -> Option<String> {
        Some("kmip-server.cloudshsm.com".to_string())
    }
}
