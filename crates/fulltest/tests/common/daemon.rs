use std::{
    io,
    net::{Ipv6Addr, SocketAddr, TcpListener},
    process::Command,
};

use command_fds::{CommandFdExt, FdMapping};
use domain_kmip::dep::kmip_protocol::net::{TlsClientAuth, TlsServerAuth};
use tempfile::TempDir;

use crate::common::hsms::Hsm;

/// A running `cascade-hsm-bridge` daemon.
pub struct Daemon<'a> {
    /// The address of the KMIP server.
    address: SocketAddr,

    /// The daemon process.
    process: std::process::Child,

    /// The temporary directory holding the daemon's state.
    tempdir: &'a tempfile::TempDir,
}

impl<'a> Daemon<'a> {
    /// Launch a new [`Daemon`].
    pub fn launch(tempdir: &'a TempDir, hsm: &impl Hsm) -> io::Result<Self> {
        // Bind a TCP socket for the KMIP server.
        let sock = TcpListener::bind((Ipv6Addr::LOCALHOST, 0))?;
        let addr = sock.local_addr()?;

        // Configure the daemon.
        let config_path = tempdir.path().join("config.toml");
        let log_path = tempdir.path().join("log");
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
        let proc = Command::new(&daemon_path)
            .arg("--config")
            .arg(&config_path)
            .fd_mappings(vec![FdMapping {
                parent_fd: sock.into(),
                child_fd: 3,
            }])
            .unwrap()
            .env("LISTEN_FDS", "1")
            .envs(hsm.env_vars())
            .current_dir(tempdir.path())
            .spawn()?;

        Ok(Self {
            address: addr,
            process: proc,
            tempdir,
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

impl<'a> Drop for Daemon<'a> {
    fn drop(&mut self) {
        // Stop the daemon.
        // TODO: Use SIGTERM?
        let _ = self.process.kill();

        if std::thread::panicking() {
            // Try to provide the daemon log file.
            if let Ok(log) = std::fs::read_to_string(self.tempdir.path().join("log")) {
                eprintln!("cascade-hsm-bridge log:\n{log}");
            }
        }
    }
}
