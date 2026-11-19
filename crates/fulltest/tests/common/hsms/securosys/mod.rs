use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::{self},
    net::{SocketAddr, ToSocketAddrs},
    option::Option,
    path::PathBuf,
    str::FromStr,
};

use domain_kmip::dep::kmip_protocol::net::{TlsClientAuth, TlsServerAuth};
use tempfile::TempDir;

use crate::common::{
    args::Args,
    hsms::{Hsm, Hsms},
    util::rename_file,
};

pub struct Securosys {
    lib_path: Option<OsString>,

    username: Option<String>,

    password: Option<String>,

    env_vars: HashMap<&'static str, String>,

    tls_ca_cert: Vec<u8>,

    tls_client_cert: Vec<u8>,

    tls_client_key: Vec<u8>,

    report_dir: Option<PathBuf>,

    securosys_log_path: Option<PathBuf>,
}

impl Securosys {
    pub fn launch(temp_dir: &TempDir, args: &Args, use_pkcs11: bool) -> io::Result<Hsms> {
        if use_pkcs11 {
            let mut env_vars = HashMap::new();

            let host = std::env::var("SECUROSYS_PKCS11_HOST")
                .expect("env var 'SECUROSYS_PKCS11_HOST' should be set")
                .to_string();
            let port = std::env::var("SECUROSYS_PKCS11_PORT")
                .expect("env var 'SECUROSYS_PKCS11_PORT' should be set")
                .to_string();
            let username = std::env::var("SECUROSYS_PKCS11_USERNAME")
                .expect("env var 'SECUROSYS_PKCS11_USERNAME' should be set")
                .to_string();

            // Configure Securosys to use a config file via which we can
            // control where it logs to, also set env vars to control which
            // API endpoint it connects to and which username it uses.
            // For more information see:
            //   https://docs.securosys.com/pkcs/Installation/pkcs11_provider_configuration/
            let securosys_config_path = temp_dir.path().join("securosys.conf");
            let securosys_log_path = args
                .report_dir()
                .map(|p| p.join("securosys.log"))
                .unwrap_or_default();
            let write_log_file = args.report_dir().is_some().to_string();
            let securosys_log_path_str = securosys_log_path.to_string_lossy().to_string();
            std::fs::write(
                &securosys_config_path,
                format!(
                    r#"
version = "1.0";
primus: {{
  connect_on_init = true;
  wait_delay      = 250;
  wait_max_tries  = 5;

  hsms: {{
    hsm0: {{
      host     = "{host}";
      port     = "{port}";
      priority = 0;
      slots: {{
        slot0: {{
          client_id = "cascade.nlnetlabs.nl";
          user_name = "{username}";
          id        = 0;
        }};
      }};
    }};
  }};

  log: {{
    file: "{securosys_log_path_str}";
    write_log_file = {write_log_file};
    write_syslog   = false;
    trace_level    = 7;
    trace_mask     = 0x00;
  }};
}};
"#
                ),
            )?;
            env_vars.insert(
                "SECUROSYS_PKCS11_CONF",
                securosys_config_path.to_string_lossy().to_string(),
            );

            // Locate the Securosys Primus PKCS#11 module.
            let lib_path = Some(std::env::var_os("SECUROSYS_PRIMARY_PKCS11_MODULE_PATH")
                .into_iter()
                .chain(
                    ["/usr/local/primus/lib/libprimusP11.so"]
                        .into_iter()
                        .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
                        .map(|v| String::from(v).into())
                )
                .next()
                .unwrap_or_else(|| panic!("could not locate the Securosys Primus PKCS#11 module! Try setting env var SECUROSYS_PRIMUS_PKCS11_MODULE_PATH.")));

            Ok(Hsms::Securosys(Self {
                lib_path,
                username: Some("0".to_string()),
                password: Some("PRIMUSDEV".to_string()),
                env_vars,
                tls_ca_cert: vec![],
                tls_client_cert: vec![],
                tls_client_key: vec![],
                report_dir: args.report_dir().cloned(),
                securosys_log_path: Some(securosys_log_path),
            }))
        } else {
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
                lib_path: None,
                username: None,
                password: None,
                env_vars,
                tls_ca_cert: std::fs::read(tls_ca_cert_path).unwrap(),
                tls_client_cert: std::fs::read(tls_client_cert_path).unwrap(),
                tls_client_key: std::fs::read(tls_client_key_path).unwrap(),
                report_dir: args.report_dir().cloned(),
                securosys_log_path: None,
            }))
        }
    }
}

impl Drop for Securosys {
    fn drop(&mut self) {
        if let Some(log_path) = &self.securosys_log_path {
            if let Some(report_dir) = &self.report_dir {
                rename_file(log_path, &report_dir.join("securosys.log"));
            } else if std::thread::panicking() {
                if let Ok(log) = std::fs::read_to_string(log_path) {
                    println!("securosys log:\n{log}");
                }
            }
        }
    }
}

impl Hsm for Securosys {
    fn lib_path(&self) -> Option<&OsStr> {
        self.lib_path.as_deref()
    }

    fn env_vars(&self) -> &HashMap<&'static str, String> {
        &self.env_vars
    }

    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    fn password(&self) -> Option<&str> {
        self.password.as_deref()
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
