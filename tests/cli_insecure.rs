//! `--insecure`: the same as setting IPPING_NODE_ALLOW_INSECURE=1, accepted before or after the
//! subcommand. Run against the real binary, with an address that is not local and does not exist,
//! so the only thing that can differ is whether the node refuses it *before* trying to connect.

use std::process::Command;

const REFUSAL: &str = "refusing to send credentials over plain http://";

fn enroll(extra: &[&str], env_insecure: bool) -> String {
    let dir = std::env::temp_dir().join(format!("ipping-node-insecure-{}", std::process::id()));
    let mut command = Command::new(env!("CARGO_BIN_EXE_ipping-node"));
    command.env_remove("IPPING_NODE_ALLOW_INSECURE");
    if env_insecure {
        command.env("IPPING_NODE_ALLOW_INSECURE", "1");
    }
    let output = command
        .args(["--state-dir", dir.to_str().unwrap()])
        .args(extra)
        .args([
            "enroll",
            "--server",
            "http://backend.invalid:8000",
            "--token",
            "not-a-real-token",
        ])
        .output()
        .expect("the binary runs");
    assert!(!output.status.success(), "there is no such server");
    let _ = std::fs::remove_dir_all(dir);
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn plain_http_to_another_host_is_refused_by_default() {
    let error = enroll(&[], false);
    assert!(error.contains(REFUSAL), "{error}");
    assert!(
        error.contains("--insecure"),
        "the message names the flag: {error}"
    );
}

#[test]
fn the_flag_allows_it_in_either_position_and_under_either_name() {
    for flags in [&["--insecure"][..], &["--allow-insecure"][..]] {
        let error = enroll(flags, false);
        assert!(!error.contains(REFUSAL), "{flags:?}: {error}");
    }
    // After the subcommand too (the flag is global), as in `ipping-node enroll ... --insecure`.
    let dir = std::env::temp_dir().join(format!("ipping-node-insecure2-{}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_ipping-node"))
        .env_remove("IPPING_NODE_ALLOW_INSECURE")
        .args([
            "--state-dir",
            dir.to_str().unwrap(),
            "enroll",
            "--server",
            "http://backend.invalid:8000",
            "--token",
            "not-a-real-token",
            "--insecure",
        ])
        .output()
        .unwrap();
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success() && !error.contains(REFUSAL),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_environment_variable_still_works() {
    let error = enroll(&[], true);
    assert!(!error.contains(REFUSAL), "{error}");
}
