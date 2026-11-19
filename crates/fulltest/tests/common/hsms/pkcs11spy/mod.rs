use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io,
    net::SocketAddr,
    option::Option,
    path::PathBuf,
};

use domain_kmip::dep::kmip_protocol::net::{TlsClientAuth, TlsServerAuth};
use tempfile::TempDir;

use crate::common::{
    args::Args,
    hsms::{Hsm, Hsms},
};

pub struct Pkcs11Spy {
    wrapped_hsm: Hsms,

    lib_path: Option<OsString>,

    env_vars: HashMap<&'static str, String>,

    pkcs11spy_log_path: Option<PathBuf>,

    report_dir: Option<PathBuf>,
}

impl Pkcs11Spy {
    pub fn wrap(wrapped_hsm: Hsms, temp_dir: &TempDir, args: &Args) -> io::Result<Self> {
        if let Some(wrapped_lib_path) = wrapped_hsm.lib_path() {
            // Find the PKCS#11 Spy module path.
            let lib_path = std::env::var_os("OPENSC_PKCS11SPY_PKCS11_MODULE_PATH")
                .into_iter()
                .chain(
                    [
                        "/lib64/pkcs11-spy.so",
                        "/usr/lib/x86_64-linux-gnu/pkcs11-spy.so"
                    ]
                    .into_iter()
                    .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
                    .map(|v| String::from(v).into()),
                )
                .next()
                .unwrap_or_else(|| {
                    panic!("could not locate the OpenSC PKCS#11 Spy PKCS#11 module! Try setting env var OPENSC_PKCS11SPY_PKCS11_MODULE_PATH.")
                });

            // Configure PKCS#11 Spy to load the PKCS#11 module to wrap.
            // See:
            //   https://github.com/OpenSC/OpenSC/wiki/Using-OpenSC#pkcs-11-spy
            let pkcs11spy_log_path = temp_dir.path().join("pkcs11spy.log");
            let mut env_vars = wrapped_hsm.env_vars().clone();
            env_vars.insert("PKCS11SPY", wrapped_lib_path.to_string_lossy().to_string());
            env_vars.insert(
                "PKCS11SPY_OUTPUT",
                format!("{}", pkcs11spy_log_path.display()),
            );

            Ok(Self {
                wrapped_hsm,
                lib_path: Some(lib_path),
                env_vars,
                pkcs11spy_log_path: Some(pkcs11spy_log_path),
                report_dir: args.report_dir().cloned(),
            })
        } else {
            let env_vars = wrapped_hsm.env_vars().clone();
            Ok(Self {
                wrapped_hsm,
                lib_path: None,
                env_vars,
                pkcs11spy_log_path: None,
                report_dir: args.report_dir().cloned(),
            })
        }
    }

    pub fn skip(hsm: Hsms) -> io::Result<Self> {
        let lib_path = hsm.lib_path().map(Into::into);
        let env_vars = hsm.env_vars().clone();
        Ok(Self {
            wrapped_hsm: hsm,
            lib_path,
            env_vars,
            pkcs11spy_log_path: None,
            report_dir: None,
        })
    }
}

impl std::fmt::Display for Pkcs11Spy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pkcs11Spy({})", self.wrapped_hsm)
    }
}

impl Drop for Pkcs11Spy {
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
    }
}

impl Hsm for Pkcs11Spy {
    fn lib_path(&self) -> Option<&OsStr> {
        self.lib_path.as_deref()
    }

    fn env_vars(&self) -> &HashMap<&'static str, String> {
        &self.env_vars
    }

    fn username(&self) -> Option<&str> {
        self.wrapped_hsm.username()
    }

    fn password(&self) -> Option<&str> {
        self.wrapped_hsm.password()
    }

    fn address(&self) -> Option<SocketAddr> {
        self.wrapped_hsm.address()
    }

    fn tls_client_auth(&self) -> Option<TlsClientAuth> {
        self.wrapped_hsm.tls_client_auth()
    }

    fn tls_server_auth(&self) -> TlsServerAuth {
        self.wrapped_hsm.tls_server_auth()
    }

    fn tls_server_name(&self) -> Option<String> {
        self.wrapped_hsm.tls_server_name()
    }

    fn current_dir(&self) -> Option<PathBuf> {
        self.wrapped_hsm.current_dir()
    }
}
