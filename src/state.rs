//! The node's identity on disk.
//!
//! Two files in the state directory, both created with mode 0600 inside a 0700 directory:
//! `node.json` (which backend, which node id) and `credential` (the secret the backend issued at
//! enrollment, shown to the node exactly once). The credential never appears in a URL, a log
//! line or an environment variable.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Base URL of the backend, for example `https://ping.example.com`.
    pub server: String,
    pub node_id: String,
}

#[derive(Debug, Clone)]
pub struct Loaded {
    pub identity: Identity,
    pub credential: String,
}

pub struct StateDir(PathBuf);

impl StateDir {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self(path.into())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    fn identity_path(&self) -> PathBuf {
        self.0.join("node.json")
    }

    fn credential_path(&self) -> PathBuf {
        self.0.join("credential")
    }

    pub fn save(&self, identity: &Identity, credential: &str) -> io::Result<()> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.0)?;
        write_private(&self.credential_path(), credential.as_bytes())?;
        write_private(
            &self.identity_path(),
            &serde_json::to_vec_pretty(identity).map_err(io::Error::other)?,
        )
    }

    /// `Ok(None)` when the node has not been enrolled yet.
    pub fn load(&self) -> io::Result<Option<Loaded>> {
        let credential = match fs::read_to_string(self.credential_path()) {
            Ok(text) => text.trim().to_owned(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let identity = serde_json::from_slice(&fs::read(self.identity_path())?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("node.json: {e}")))?;
        let mode = fs::metadata(self.credential_path())?.permissions().mode();
        if mode & 0o077 != 0 {
            tracing::warn!(
                path = %self.credential_path().display(),
                mode = format_args!("{:o}", mode & 0o777),
                "credential file is readable by other users; run chmod 600 on it"
            );
        }
        Ok(Some(Loaded {
            identity,
            credential,
        }))
    }
}

/// Write via a temporary file and rename, so a crash never leaves a half-written credential.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ipping-node-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn saved_identity_loads_back_and_files_are_private() {
        let dir = temp_dir("state");
        let state = StateDir::new(dir.join("nested"));
        assert!(state.load().unwrap().is_none());

        let identity = Identity {
            server: "https://ping.example.com".into(),
            node_id: "abc".into(),
        };
        state.save(&identity, "abc.secret\n").unwrap();
        let loaded = state.load().unwrap().unwrap();
        assert_eq!(loaded.identity, identity);
        assert_eq!(loaded.credential, "abc.secret");

        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(state.path()), 0o700);
        assert_eq!(mode(&state.path().join("credential")), 0o600);
        assert_eq!(mode(&state.path().join("node.json")), 0o600);
        let _ = fs::remove_dir_all(dir);
    }
}
