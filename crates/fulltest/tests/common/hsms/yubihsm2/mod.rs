use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io,
    path::PathBuf,
};

use tempfile::TempDir;

use crate::common::hsms::{Hsm, Hsms};

pub struct Yubihsm2 {
    lib_path: OsString,

    env_vars: HashMap<&'static str, String>,

    log_path: std::path::PathBuf,

    report_dir: Option<PathBuf>,
}

impl Yubihsm2 {
    pub fn launch(tempdir: &TempDir, report_dir: &Option<PathBuf>) -> io::Result<Hsms> {
        let lib_path = std::env::var_os("YUBIHSM_PKCS11_MODULE")
            .into_iter()
            .chain(
                [
                    "/usr/lib64/pkcs11/yubihsm_pkcs11.so", // Fedora 43
                ]
                .into_iter()
                .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
                .map(|v| String::from(v).into()),
            )
            .next()
            .unwrap_or_else(|| panic!("could not locate the YubiHSM2 PKCS#11 module! Try setting env var YUBIHSM_PKCS11_MODULE."));

        let hsm_config_path = tempdir.path().join("yubihsm_pkcs11.conf");
        let log_path = tempdir.path().join("yubihsm.log");
        let log_path_str = log_path.to_str().unwrap();
        std::fs::write(
            &hsm_config_path,
            format!(
                r#"
connector = http://127.0.0.1:12345
debug
debug-file = {log_path_str}
timeout = 5
"#
            ),
        )?;

        let mut env_vars = HashMap::new();
        env_vars.insert(
            "YUBIHSM_PKCS11_CONF",
            hsm_config_path.to_string_lossy().to_string(),
        );

        Ok(Hsms::Yubihsm2(Self {
            lib_path,
            env_vars,
            report_dir: report_dir.clone(),
            log_path,
        }))
    }
}

impl Drop for Yubihsm2 {
    fn drop(&mut self) {
        if let Some(report_dir) = &self.report_dir {
            std::fs::rename(&self.log_path, report_dir.join("yubihsm2.log")).unwrap();
        } else if std::thread::panicking() {
            if let Ok(log) = std::fs::read_to_string(&self.log_path) {
                println!("yubihsm2 log:\n{log}");
            }
        }
    }
}

impl Hsm for Yubihsm2 {
    fn lib_path(&self) -> Option<&OsStr> {
        Some(&self.lib_path)
    }

    fn env_vars(&self) -> &HashMap<&'static str, String> {
        &self.env_vars
    }

    fn username(&self) -> std::option::Option<&str> {
        Some("0")
    }

    fn password(&self) -> std::option::Option<&str> {
        // This is the default admin password for a YubiHSM2.
        Some("0001password")
    }
}
