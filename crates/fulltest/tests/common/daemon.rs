use std::{
    io::{self},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    process::Command,
};

use command_fds::{CommandFdExt, FdMapping};
use domain_kmip::dep::kmip_protocol::net::{TlsClientAuth, TlsServerAuth};
use tempfile::TempDir;

use crate::common::{
    args::Args,
    hsms::Hsm,
    util::{extract_human_readable_kmip_messages, rename_file},
};

/// A running `cascade-hsm-bridge` daemon.
pub struct Daemon {
    /// The address of the KMIP server.
    address: SocketAddr,

    /// The daemon process.
    process: std::process::Child,

    log_path: PathBuf,

    report_dir: Option<PathBuf>,

    hex_to_txt_bin_path: Option<PathBuf>,
}

impl Daemon {
    /// Launch a new [`Daemon`].
    pub fn launch(
        temp_dir: &TempDir,
        args: &Args,
        current_dir: Option<PathBuf>,
        hsm: &impl Hsm,
    ) -> io::Result<Self> {
        // Bind a TCP socket for the KMIP server.
        let sock = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let addr = sock.local_addr()?;

        // Configure the daemon.
        let config_path = temp_dir.path().join("config.toml");
        let log_path = temp_dir.path().join("cascade-hsm-bridge.log");
        let lib_path = hsm.lib_path().unwrap();

        // TODO: Use <https://crates.io/crates/indoc>?
        std::fs::write(
            &config_path,
            format!(
                r#"
version = "v1"
pkcs11.lib-path = {lib_path:?}
daemon.log-level = "trace"
daemon.log-target = {{ type = "file", path = {log_path:?} }}
"#
            ),
        )?;

        // Make sure the daemon binary is ready.
        let project_dir = std::env::current_dir()?;
        if !Command::new("cargo")
            .args([
                "build",
                "--package",
                "cascade-hsm-bridge",
                "--bin",
                "cascade-hsm-bridge",
            ])
            .spawn()?
            .wait()?
            .success()
        {
            return Err(io::Error::other("could not build 'cascade-hsm-bridge'"));
        }

        // Launch the daemon.
        let daemon_path = project_dir.join("../../target/debug/cascade-hsm-bridge");
        let mut proc = Command::new(&daemon_path);
        proc.arg("--config")
            .arg(&config_path)
            .fd_mappings(vec![FdMapping {
                parent_fd: sock.into(),
                child_fd: 3,
            }])
            .unwrap()
            .env("LISTEN_FDS", "1")
            .envs(hsm.env_vars());

        if let Some(current_dir) = current_dir {
            proc.current_dir(current_dir);
        }

        let proc = proc.spawn()?;

        println!("Cascade-HSM-Bridge is running at {addr}");

        Ok(Self {
            address: addr,
            process: proc,
            log_path,
            report_dir: args.report_dir().cloned(),
            hex_to_txt_bin_path: args.hex_to_txt_bin_path().cloned(),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn tls_client_auth(&self) -> Option<TlsClientAuth> {
        None
    }

    pub fn tls_server_auth(&self) -> TlsServerAuth {
        TlsServerAuth::None
    }

    pub fn tls_server_name(&self) -> Option<String> {
        None
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        println!("Stopping Cascade-HSM-Bridge");
        // TODO: Use SIGTERM?
        let _ = self.process.kill();

        if let Some(report_dir) = &self.report_dir {
            let stored_log_path = report_dir.join("cascade-hsm-bridge.log");
            rename_file(&self.log_path, &stored_log_path);

            extract_human_readable_kmip_messages(
                &stored_log_path,
                self.hex_to_txt_bin_path.as_deref(),
                report_dir,
            );
        } else if std::thread::panicking() {
            if let Ok(log) = std::fs::read_to_string(&self.log_path) {
                eprintln!("cascade-hsm-bridge log:\n{log}");
            }
        }
    }
}
