use std::{
    collections::HashMap, ffi::{OsStr, OsString}, io, option::Option, path::PathBuf, process::Command,
};

use tempfile::TempDir;

use crate::common::hsms::{Hsm, Hsms};

pub struct Softhsm2 {
    lib_path: OsString,

    env_vars: HashMap<&'static str, String>,

    pkcs11spy_log_path: PathBuf,

    slot_label: String,

    pin: String,

    report_dir: Option<PathBuf>,
}

impl Softhsm2 {
    pub fn launch(temp_dir: &TempDir, report_dir: &Option<PathBuf>) -> io::Result<Hsms> {
        // Determine the location of the SoftHSMv2 library.
        let softhsm_lib_path = std::env::var_os("SOFTHSM2_PATH")
            .into_iter()
            .chain(
                [
                    "/usr/lib64/pkcs11/libsofthsm2.so", // Fedora 43
                    "/usr/lib64/softhsm/libsofthsm2.so",
                    "/usr/lib/softhsm/libsofthsm2.so",
                ]
                .into_iter()
                .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
                .map(|v| String::from(v).into()),
            )
            .next()
            .unwrap_or_else(|| panic!("could not locate the SoftHSMv2 PKCS#11 module! Try setting env var SOFTHSM2_PATH."));

        // Configure SoftHSMv2.
        let tokens_path = temp_dir.path().join("tokens").display().to_string();
        let hsm_config_path = temp_dir.path().join("softhsm2.conf");
        std::fs::write(
            &hsm_config_path,
            format!(
                r#"
directories.tokendir = {tokens_path}
objectstore.backend = file
log.level = DEBUG
"#
            ),
        )?;

        // Create the tokens directory.
        std::fs::create_dir_all(&tokens_path)?;

        // Initialize the HSM slot/token.
        let slot_label = String::from("cascade-hsm-bridge-test");
        let pin = String::from("123456");
        if !Command::new("softhsm2-util")
            .args([
                "--init-token",
                "--free",
                "--label",
                &slot_label,
                "--so-pin",
                &pin,
                "--pin",
                &pin,
            ])
            .env("SOFTHSM2_CONF", &hsm_config_path)
            .spawn()?
            .wait()?
            .success()
        {
            return Err(io::Error::other("could not initialize SoftHSMv2"));
        }

        // Configure PKCS#11 Spy to load the SoftHSMv2 PKCS#11 module.
        // See:
        //   https://github.com/OpenSC/OpenSC/wiki/Using-OpenSC#pkcs-11-spy
        let pkcs11spy_log_path = temp_dir.path().join("pkcs11spy.log");
        let mut env_vars = HashMap::new();
        env_vars.insert("PKCS11SPY", softhsm_lib_path.into_string().unwrap());
        env_vars.insert(
            "PKCS11SPY_OUTPUT",
            format!("{}", pkcs11spy_log_path.display()),
        );

        // Find the PKCS#11 Spy module path.
        let lib_path = 
            std::env::var_os("OPENSC_PKCS11SPY_PKCS11_MODULE_PATH")
                .into_iter()
                .chain(
                    ["/lib64/pkcs11-spy.so"]
                        .into_iter()
                        .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
                        .map(|v| String::from(v).into()),
                )
                .next()
                .unwrap_or_else(|| {
                    panic!("could not locate the OpenSC PKCS#11 Spy PKCS#11 module! Try setting env var OPENSC_PKCS11SPY_PKCS11_MODULE_PATH.")
                });

        env_vars.insert(
            "SOFTHSM2_CONF",
            hsm_config_path.to_string_lossy().to_string(),
        );

        Ok(Hsms::Softhsm2(Self {
            lib_path,
            env_vars,
            pkcs11spy_log_path,
            slot_label,
            pin,
            report_dir: report_dir.clone(),
        }))
    }
}

impl Drop for Softhsm2 {
    fn drop(&mut self) {
        if let Some(report_dir) = &self.report_dir {
            std::fs::rename(&self.pkcs11spy_log_path, report_dir.join("pkcs11spy.log")).unwrap();
        } else if std::thread::panicking() {
            if let Ok(log) = std::fs::read_to_string(&self.pkcs11spy_log_path) {
                println!("pkcs11spy log:\n{log}");
            }
        }
    }
}

impl Hsm for Softhsm2 {
    fn lib_path(&self) -> Option<&OsStr> {
        Some(&self.lib_path)
    }

    fn env_vars(&self) -> &HashMap<&'static str, String> {
        &self.env_vars
    }

    fn username(&self) -> Option<&str> {
        Some(&self.slot_label)
    }

    fn password(&self) -> Option<&str> {
        Some(&self.pin)
    }
}
