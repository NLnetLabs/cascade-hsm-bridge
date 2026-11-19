use std::path::PathBuf;

use chrono::Local;
use clap::Parser;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Path to write captured logs to.
    ///
    /// Set to `auto` to output to `integration-test-reports/YYYY-MM-DD-<HSM NAME>`.
    #[arg(long, value_parser = clap::value_parser!(PathBuf), default_value = None)]
    report_dir: Option<PathBuf>,

    /// Path to hex-to-txt binary.
    ///
    /// Used to extract KMIP messages from the Cascade-HSM-Bridge log.
    #[arg(long, default_value = None)]
    hex_to_txt_bin_path: Option<PathBuf>,

    /// Wrap PKCS#11 modules with OpenSC pkcs11-spy.
    ///
    /// Enables logging of PKCS#11 calls.
    #[arg(long, default_value_t = false)]
    pkcs11spy: bool,

    /// HSM to test.
    #[arg(default_value_t = "softhsm2".to_string(), value_parser = ["fortanixdsm", "fortanixdsm-pkcs11", "kryoptic", "nethsm", "pykmip", "securosys", "securosys-pkcs11", "softhsm2", "thales", "yubihsm2"])]
    hsm: String,
}

impl Args {
    pub fn report_dir(&self) -> Option<&PathBuf> {
        self.report_dir.as_ref()
    }

    pub fn hex_to_txt_bin_path(&self) -> Option<&PathBuf> {
        self.hex_to_txt_bin_path.as_ref()
    }

    pub fn pkcs11spy(&self) -> bool {
        self.pkcs11spy
    }

    pub fn hsm(&self) -> &str {
        &self.hsm
    }

    pub fn process_report_dir(mut self) -> Args {
        if let Some(report_dir) = &self.report_dir {
            if report_dir.as_os_str() == "auto" {
                let integration_test_reports_dir = PathBuf::from("../../integration-test-reports");
                if !integration_test_reports_dir.exists() {
                    panic!(
                        "Cannot generate 'auto' report-dir path: '{}' does not exist",
                        integration_test_reports_dir.display()
                    );
                }
                let date = Local::now().format("%Y-%m-%d").to_string();
                let hsm = &self.hsm;
                self.report_dir = Some(integration_test_reports_dir.join(format!("{date}-{hsm}")));
            }
        }
        self
    }
}
