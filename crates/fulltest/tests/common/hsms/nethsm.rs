use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    io,
};

use chrono::Utc;
use tempfile::TempDir;

use crate::common::hsms::{Hsm, Hsms};

// TODO: https://github.com/fussybeaver/bollard/blob/master/examples/exec.rs

pub struct Nethsm {
    lib_path: OsString,

    env_vars: HashMap<&'static str, String>,
}

impl Nethsm {
    /// Assumes that the NetHSM is already running at NETHSM_HOST env var, or
    /// 127.0.0.1:8443.
    ///
    /// The NetHSM can be launched like so:
    ///
    /// docker run --rm -ti -p 127.0.0.1:8443:8443 docker.io/nitrokey/nethsm:testing
    pub fn launch(tempdir: &TempDir) -> io::Result<Hsms> {
        let nethsm_host = std::env::var("NETHSM_HOST").unwrap_or("127.0.0.1:8443".into());

        // Determine the location of the NetHSM library.
        let lib_path = std::env::var_os("NETHSM_PKCS11_PATH")
            .into_iter()
            .chain(
        [
            "/usr/lib64/pkcs11/nethsm-pkcs11-v3.0.1-x86_64-linux-glibc.so", // Fedora 43
        ]
        .into_iter()
        .filter(|&p| std::fs::exists(p).is_ok_and(|v| v))
        .map(|v| String::from(v).into()))
        .next()
        .unwrap_or_else(|| panic!("could not locate the NetHSM PKCS#11 module! Try setting env var NETHSM_PKCS11_PATH"));

        let password = "unlockpass32768".to_string();

        let hsm_config_path = tempdir.path().join("p11nethsm.conf");
        std::fs::write(
            &hsm_config_path,
            format!(
                r#"
enable_set_attribute_value: false
log_level: Info
log_file: "-"

slots:
  - label: LocalHSM                        # Name your NetHSM however you want
    description: Local HSM (docker)        # Optional description
    operator:
      username: "opuser"
      password: "{password}"
    administrator:
      username: "opadmin"
      password: "{password}"

    instances:
      - url: "https://{nethsm_host}/api/v1"   # URL to reach the server
        max_idle_connections: 10
        danger_insecure_cert: true
    retries:
      count: 3
      delay_seconds: 1
    tcp_keepalive:
      time_seconds: 600
      interval_seconds: 60
      retries: 3
    connections_max_idle_duration: 1800
    timeout_seconds: 10
"#
            ),
        )?;

        // Initialize the HSM slot/token.
        // Based on: https://github.com/niek-sidn/hsm_workshop_nethsm/blob/main/files/hsm-client/provision_hsm.sh
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        #[allow(non_snake_case)]
        let API: String = format!("https://{nethsm_host}/api/v1");

        let res = client.get(format!("{API}/health/state")).send().unwrap();
        assert_eq!(res.status().as_u16(), 200);

        let health_state = res.json::<HealthState>().unwrap();
        if health_state.state == "Unprovisioned" {
            let time_now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            println!("Provisioning NetHSM: time now = {time_now}");

            let mut provision_args = HashMap::new();
            provision_args.insert("unlockPassphrase", &password);
            provision_args.insert("adminPassphrase", &password);
            provision_args.insert("systemTime", &time_now);
            let res = client
                .post(format!("{API}/provision"))
                .json(&provision_args)
                .send()
                .unwrap();
            assert_eq!(res.status().as_u16(), 204);

            let mut unattended_boot_args = HashMap::new();
            unattended_boot_args.insert("status", "on");
            let res = client
                .put(format!("{API}/config/unattended-boot"))
                .basic_auth("admin", Some(&password))
                .json(&unattended_boot_args)
                .send()
                .unwrap();
            assert_eq!(res.status().as_u16(), 204);

            let mut users_operator_args = HashMap::new();
            users_operator_args.insert("realName", "Nitrokey Operator");
            users_operator_args.insert("role", "Operator");
            users_operator_args.insert("passphrase", &password);
            let res = client
                .put(format!("{API}/users/opuser"))
                .basic_auth("admin", Some(&password))
                .json(&users_operator_args)
                .send()
                .unwrap();
            assert_eq!(res.status().as_u16(), 201);

            let mut users_operator_args = HashMap::new();
            users_operator_args.insert("realName", "Nitrokey Admin");
            users_operator_args.insert("role", "Administrator");
            users_operator_args.insert("passphrase", &password);
            let res = client
                .put(format!("{API}/users/opadmin"))
                .basic_auth("admin", Some(&password))
                .json(&users_operator_args)
                .send()
                .unwrap();
            assert_eq!(res.status().as_u16(), 201);
        }

        let mut env_vars = HashMap::new();
        env_vars.insert(
            "P11NETHSM_CONFIG_FILE",
            hsm_config_path.to_string_lossy().to_string(),
        );

        Ok(Hsms::Nethsm(Self { lib_path, env_vars }))
    }
}

impl Hsm for Nethsm {
    fn lib_path(&self) -> Option<&OsStr> {
        Some(&self.lib_path)
    }

    fn env_vars(&self) -> &HashMap<&'static str, String> {
        &self.env_vars
    }

    fn username(&self) -> Option<&str> {
        Some("LocalHSM")
    }

    fn password(&self) -> Option<&str> {
        Some("NotUsedButNeedsToBeSetToSomething")
    }
}

#[derive(Debug, serde::Deserialize)]
struct HealthState {
    state: String,
}
