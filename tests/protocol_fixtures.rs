//! The example frames in `tests/fixtures/` are copied from the backend's `contracts/fixtures/`.
//! These tests fail if this crate's protocol types drift away from them.

use std::fs;
use std::path::PathBuf;

use ipping_node::protocol::{ClientFrame, ServerFrame};
use serde_json::Value;

fn fixtures(direction: &str) -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(direction);
    let mut found: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            (
                name,
                serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap(),
            )
        })
        .collect();
    found.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!found.is_empty(), "no fixtures in {}", dir.display());
    found
}

#[test]
fn every_backend_frame_parses() {
    for (name, json) in fixtures("backend-to-node") {
        serde_json::from_value::<ServerFrame>(json.clone())
            .unwrap_or_else(|e| panic!("backend-to-node/{name}.json: {e}"));
    }
}

#[test]
fn every_node_frame_round_trips_exactly() {
    // Parsing a fixture and writing it back must give the same JSON: nothing is dropped,
    // renamed or invented.
    for (name, json) in fixtures("node-to-backend") {
        let frame: ClientFrame = serde_json::from_value(json.clone())
            .unwrap_or_else(|e| panic!("node-to-backend/{name}.json: {e}"));
        assert_eq!(
            serde_json::to_value(&frame).unwrap(),
            json,
            "node-to-backend/{name}.json"
        );
    }
}

#[test]
fn unknown_fields_in_backend_frames_are_ignored() {
    let frame: ServerFrame =
        serde_json::from_str(r#"{"type":"cancel","task_id":"t","added_later":true}"#).unwrap();
    assert!(matches!(frame, ServerFrame::Cancel { task_id } if task_id == "t"));
}

#[test]
fn unknown_frame_types_do_not_parse() {
    // The connection loop logs and skips these instead of dropping the connection.
    assert!(serde_json::from_str::<ServerFrame>(r#"{"type":"from_the_future"}"#).is_err());
}
