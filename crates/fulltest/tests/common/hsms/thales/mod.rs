use std::{
    collections::HashMap, ffi::{OsStr, OsString}, io, option::Option, path::PathBuf,
};

use tempfile::TempDir;

use crate::common::hsms::{Hsm, Hsms};

pub struct ThalesDPOD {
    lib_path: OsString,

    env_vars: HashMap<&'static str, String>,

    slot_label: String,

    pin: String,
}

impl ThalesDPOD {
    pub fn launch() -> io::Result<Hsms> {
        // Determine the location of the ThalesDPOD library.
        let lib_path = std::env::var_os("THALES_DPOD_PKCS11_MODULE_PATH")
            .into_iter()
            .chain(
                [
                    "/usr/local/dpodclient/libs/64/libCryptoki2.so",
                ]
                .into_iter()
                .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
                .map(|v| String::from(v).into()),
            )
            .next()
            .unwrap_or_else(|| panic!("could not locate the ThalesDPOD PKCS#11 module! Try setting env var THALES_DPOD_PKCS11_MODULE_PATH."));

        let mut env_vars = HashMap::new();
        env_vars.insert(
            "ChrystokiConfigurationPath",
            "/usr/local/dpodclient".to_string(),
        );

        let slot_label = "MyPartition".to_string();
        let pin = "mycopassword".to_string();

        Ok(Hsms::Thales(Self {
            lib_path,
            env_vars,
            slot_label,
            pin,
        }))
    }
}

impl Hsm for ThalesDPOD {
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

    fn current_dir(&self) -> Option<PathBuf> {
        // Without this the module appears to have no initialized slots...
        Some(PathBuf::new("/usr/local/dpodclient"))
    }
}
