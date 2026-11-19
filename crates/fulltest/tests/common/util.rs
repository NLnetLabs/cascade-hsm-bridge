use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

pub fn extract_human_readable_kmip_messages(
    in_log_path: &Path,
    hex_to_txt_bin_path: &Path,
    report_dir: &Path,
) {
    // Open a report file for writing.
    let mut kmip_report = std::fs::File::create_new(report_dir.join("kmip.log")).unwrap();

    // Attempt to extract all KMIP exchanges and generate human
    // readable equivalents of them. This feels like a bit too
    // much to be doing in a Drop impl...
    let log = std::fs::read_to_string(&in_log_path).unwrap();

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
