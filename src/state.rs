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
            Err(error) => return Err(explain(&self.credential_path(), error)),
        };
        let identity_bytes = fs::read(self.identity_path())
            .map_err(|error| explain(&self.identity_path(), error))?;
        let identity = serde_json::from_slice(&identity_bytes)
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

/// Say which file could not be read and, for the commonest cause, how to fix it: the node runs as
/// its own account, and files left by someone else (for example an `enroll` run as root) are
/// unreadable to it.
fn explain(path: &Path, error: io::Error) -> io::Error {
    if error.kind() != io::ErrorKind::PermissionDenied {
        return io::Error::new(error.kind(), format!("{}: {error}", path.display()));
    }
    let directory = path.parent().unwrap_or(path);
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "{}: {error}. The state directory and the files in it must belong to the account the \
             node runs as (often `ipping-node`); if they were created by another account, for \
             example by running `enroll` as root, fix that with: sudo chown -R ipping-node: {}",
            path.display(),
            directory.display()
        ),
    )
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

    #[test]
    fn a_file_the_account_cannot_read_is_named_with_the_fix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("denied");
        let state = StateDir::new(&dir);
        state
            .save(
                &Identity {
                    server: "https://ping.example.com".into(),
                    node_id: "abc".into(),
                },
                "secret",
            )
            .unwrap();
        fs::set_permissions(dir.join("credential"), fs::Permissions::from_mode(0o000)).unwrap();
        // root can read anything, so only check where the permission really is denied.
        if let Err(error) = state.load() {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            let text = error.to_string();
            assert!(text.contains("credential"), "{text}");
            assert!(text.contains("chown -R"), "{text}");
        }
        fs::set_permissions(dir.join("credential"), fs::Permissions::from_mode(0o600)).unwrap();
        let _ = fs::remove_dir_all(dir);
    }
}
