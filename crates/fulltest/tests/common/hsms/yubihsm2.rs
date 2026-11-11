use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io,
};

use tempfile::TempDir;

use crate::common::hsms::{Hsm, Hsms};

pub struct Yubihsm2 {
    lib_path: OsString,

    env_vars: HashMap<&'static str, String>,
}

impl Yubihsm2 {
    pub fn launch(tempdir: &TempDir) -> io::Result<Hsms> {
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
            .unwrap_or_else(|| panic!("could not locate the YubiHSM2 PKCS#11 module!"));

        let hsm_config_path = tempdir.path().join("yubihsm_pkcs11.conf");
        std::fs::write(
            &hsm_config_path,
            format!(
                r#"
connector = http://127.0.0.1:12345
debug
#dinout
#libdebug
#debug-file = /tmp/yuibhsm_pkcs11_debug
#cacert = /tmp/cacert.pem
#proxy = http://proxyserver.local.com:8080
timeout = 5
"#
            ),
        )?;

        let mut env_vars = HashMap::new();
        env_vars.insert(
            "YUBIHSM_PKCS11_CONF",
            hsm_config_path.to_string_lossy().to_string(),
        );

        Ok(Hsms::Yubihsm2(Self { lib_path, env_vars }))
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
