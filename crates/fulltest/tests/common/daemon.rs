use std::{
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::PathBuf,
    process::{Command, Stdio},
};

use command_fds::{CommandFdExt, FdMapping};
use domain_kmip::dep::kmip_protocol::net::{TlsClientAuth, TlsServerAuth};
use tempfile::TempDir;

use crate::common::hsms::Hsm;

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
        report_dir: &Option<PathBuf>,
        hex_to_txt_bin_path: Option<PathBuf>,
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
            .current_dir(temp_dir.path())
            .spawn()?;

        println!("Cascade-HSM-Bridge is running at {addr}");

        Ok(Self {
            address: addr,
            process: proc,
            log_path,
            report_dir: report_dir.clone(),
            hex_to_txt_bin_path,
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
            let final_log_path = report_dir.join("cascade-hsm-bridge.log");
            std::fs::rename(&self.log_path, &final_log_path).unwrap();

            if let Some(hex_to_txt_bin_path) = &self.hex_to_txt_bin_path {
                // Open a report file for writing.
                let mut kmip_report =
                    std::fs::File::create_new(report_dir.join("kmip.log")).unwrap();

                // Attempt to extract all KMIP exchanges and generate human
                // readable equivalents of them. This feels like a bit too
                // much to be doing in a Drop impl...
                let log = std::fs::read_to_string(&final_log_path).unwrap();

                // Find all of the log messages saying they are reading or writing
                // KMIP messages from/to the client. 4200 is the start of a KMIP
                // tag in hex. With the ": " preceeding it it denotes the start of
                // the entire KMIP message. The end of the message is when the hex
                // bytes run out.
                for (start_idx, _) in log.match_indices(": 4200") {
                    let hex_start_idx = start_idx + 2;
                    // Find the end of the hex bytes.
                    if let Some(end_idx) = log.split_at(hex_start_idx).1.find(|c: char| {
                        let res = !c.is_ascii_hexdigit();
                        res
                    }) {
                        let end_idx = hex_start_idx + end_idx;
                        // Extract the KMIP hex bytes.
                        let kmip_hex_bytes = &log[hex_start_idx..=end_idx];

                        // Convert it to human readable text.
                        // Based on: https://doc.rust-lang.org/std/process/struct.Stdio.html#method.piped
                        let mut hex_to_txt = Command::new(hex_to_txt_bin_path)
                            .args(["-"])
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .spawn()
                            .expect("hex_to_txt command should start");

                        let mut stdin = hex_to_txt.stdin.take().unwrap();
                        let bytes_to_write = kmip_hex_bytes.as_bytes().to_vec();
                        let join_handle = std::thread::spawn(move || {
                            stdin.write_all(&bytes_to_write).unwrap();
                        });

                        let hex_to_txt_stdout = hex_to_txt.wait_with_output().unwrap().stdout;
                        join_handle.join().unwrap();
                        let human_readable = String::from_utf8_lossy(&hex_to_txt_stdout);

                        // Write the KMIP bytes and the readable version to a report file.
                        writeln!(kmip_report, "Raw KMIP:\n{kmip_hex_bytes}").unwrap();
                        writeln!(kmip_report, "Rendered:\n{human_readable}").unwrap();
                        writeln!(kmip_report).unwrap();
                    }
                }
            }
        } else if std::thread::panicking() {
            if let Ok(log) = std::fs::read_to_string(&self.log_path) {
                eprintln!("cascade-hsm-bridge log:\n{log}");
            }
        }
    }
}
