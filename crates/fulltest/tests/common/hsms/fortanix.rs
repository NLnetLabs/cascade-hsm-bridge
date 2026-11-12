use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io::{self},
    net::{SocketAddr, ToSocketAddrs},
    option::Option,
    path::PathBuf,
};

use domain_kmip::dep::kmip_protocol::net::{TlsClientAuth, TlsServerAuth};
use tempfile::TempDir;

use crate::common::hsms::{Hsm, Hsms};

pub struct FortanixDSM {
    env_vars: HashMap<&'static str, String>,

    lib_path: Option<OsString>,

    pkcs11spy_log_path: Option<PathBuf>,

    fortanix_log_path: Option<PathBuf>,

    username: String,

    password: String,

    report_dir: Option<PathBuf>,
}

impl FortanixDSM {
    pub fn launch(
        temp_dir: &TempDir,
        report_dir: &Option<PathBuf>,
        use_pkcs11: bool,
    ) -> io::Result<Hsms> {
        let username;
        let password;
        let mut lib_path = None;
        let mut pkcs11spy_log_path = None;
        let mut fortanix_log_path = None;
        let mut env_vars = HashMap::new();

        if use_pkcs11 {
            // Direct the Fortanix PKCS#11 module to use PKCS#11 slot number
            // 1 (sent as the KMIP username to the bridge which is then used
            // as the slot index to request from the PKCS#11 module).
            username = "1".to_string();

            // Configure Fortanix to use a config file via which we can
            // control where it logs to, also set env vars to control which
            // API endpoint it connects to and which API key it uses.
            // For more information see:
            //   https://support.fortanix.com/docs/fortanix-dsm-clients-pkcs11-library#61-user-pin
            let fortanix_config_path = temp_dir.path().join("fortanix.conf");
            fortanix_log_path = Some(temp_dir.path().join("fortanix.log"));
            let fortanix_log_path_str = fortanix_log_path
                .as_ref()
                .unwrap()
                .to_string_lossy()
                .to_string();
            std::fs::write(
                &fortanix_config_path,
                format!(
                    r#"
[log]
file = "{fortanix_log_path_str}"
level = "trace"
"#
                ),
            )?;

            password = std::env::var("FORTANIX_API_KEY")
                .expect("env var 'FORTANIX_API_KEY' should be set")
                .to_string();
            env_vars.insert(
                "FORTANIX_API_ENDPOINT",
                "https://eu.smartkey.io".to_string(),
            );
            env_vars.insert(
                "FORTANIX_PKCS11_CONFIG_PATH",
                format!("{}", fortanix_config_path.display()),
            );

            // Locate the Fortanix DSM PKCS#11 module.
            let fortanix_dsm_lib_path = std::env::var("FORTANIX_DSM_PKCS11_MODULE_PATH")
                .into_iter()
                .chain(
                    ["/opt/fortanix/pkcs11/fortanix_pkcs11.so"]
                        .into_iter()
                        .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
                        .map(ToString::to_string),
                )
                .next()
                .unwrap_or_else(|| panic!("could not locate the Fortanix DSM PKCS#11 module! Try setting env var FORTANIX_DSM_PKCS11_MODULE_PATH."));

            // Configure PKCS#11 Spy to load the Fortanix DSM PKCS#11 module.
            // See:
            //   https://github.com/OpenSC/OpenSC/wiki/Using-OpenSC#pkcs-11-spy
            pkcs11spy_log_path = Some(temp_dir.path().join("pkcs11spy.log"));
            env_vars.insert("PKCS11SPY", fortanix_dsm_lib_path);
            env_vars.insert(
                "PKCS11SPY_OUTPUT",
                format!("{}", pkcs11spy_log_path.as_ref().unwrap().display()),
            );

            // Find the PKCS#11 Spy module path.
            lib_path = Some(
                std::env::var_os("OPENSC_PKCS11SPY_PKCS11_MODULE_PATH")
                    .into_iter()
                    .chain(
                        ["/lib64/pkcs11pkcs11-spy.so"]
                            .into_iter()
                            .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
                            .map(|v| String::from(v).into()),
                    )
                    .next()
                    .unwrap_or_else(|| {
                        panic!("could not locate the OpenSC PKCS#11 Spy PKCS#11 module! Try setting env var OPENSC_PKCS11SPY_PKCS11_MODULE_PATH.")
                    }),
            );
        } else {
            username =
                std::env::var("FORTANIX_USER").expect("env var 'FORTANIX_USER' should be set");
            password =
                std::env::var("FORTANIX_PASS").expect("env var 'FORTANIX_PASS' should be set");
        }

        Ok(Hsms::Fortanix(Self {
            env_vars,
            lib_path,
            pkcs11spy_log_path,
            fortanix_log_path,
            username,
            password,
            report_dir: report_dir.clone(),
        }))
    }
}

impl Drop for FortanixDSM {
    fn drop(&mut self) {
        if let Some(pkcs11spy_log_path) = &self.pkcs11spy_log_path {
            if let Some(report_dir) = &self.report_dir {
                std::fs::rename(pkcs11spy_log_path, report_dir.join("pkcs11spy.log")).unwrap();
            } else if std::thread::panicking() {
                if let Ok(log) = std::fs::read_to_string(pkcs11spy_log_path) {
                    println!("pkcs11spy log:\n{log}");
                }
            }
        }
        if let Some(fortanix_log_path) = &self.fortanix_log_path {
            if let Some(report_dir) = &self.report_dir {
                std::fs::rename(fortanix_log_path, report_dir.join("fortanix.log")).unwrap();
            } else if std::thread::panicking() {
                if let Ok(log) = std::fs::read_to_string(fortanix_log_path) {
                    println!("fortanix log:\n{log}");
                }
            }
        }
    }
}

impl Hsm for FortanixDSM {
    fn lib_path(&self) -> Option<&OsStr> {
        self.lib_path.as_deref()
    }

    fn env_vars(&self) -> &HashMap<&'static str, String> {
        &self.env_vars
    }

    fn username(&self) -> Option<&str> {
        Some(&self.username)
    }

    fn password(&self) -> Option<&str> {
        Some(&self.password)
    }

    fn address(&self) -> Option<SocketAddr> {
        "eu.smartkey.io:5696".to_socket_addrs().unwrap().next()
    }

    fn tls_client_auth(&self) -> Option<TlsClientAuth> {
        None
    }

    fn tls_server_auth(&self) -> TlsServerAuth {
        TlsServerAuth::None
    }

    fn tls_server_name(&self) -> Option<String> {
        None
    }
}
