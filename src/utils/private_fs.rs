//! Files and folders only the owner can read.
//!
//! On Unix a new wallet or backup folder is created `0700` and a new
//! database or backup file `0600`, whatever the process umask. Elsewhere the
//! platform defaults apply (the folders live in per-user locations there).

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Mode of a folder created for a wallet or its backups.
#[cfg(unix)]
pub const DIR_MODE: u32 = 0o700;
/// Mode of a database or backup file created by the crate.
#[cfg(unix)]
pub const FILE_MODE: u32 = 0o600;

/// `create_dir_all`, but every folder it creates is private to the owner.
/// Folders that already exist keep their mode.
pub fn create_dir_all(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(DIR_MODE);
    }
    builder.create(path)
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(FILE_MODE);
    }
    options
}

/// `File::create` (write, create, truncate) for a file private to the owner.
/// A file that already exists is made private too.
pub fn create_file(path: &Path) -> io::Result<File> {
    let file = private_options().truncate(true).open(path)?;
    restrict(&file)?;
    Ok(file)
}

/// Create an empty file private to the owner if `path` does not exist yet,
/// so that whatever later opens it (SQLite) inherits the mode. An existing
/// file is left as it is.
pub fn touch_new(path: &Path) -> io::Result<()> {
    match private_options().create_new(true).open(path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn restrict(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(FILE_MODE))
}

#[cfg(not(unix))]
fn restrict(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
pub(crate) fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_new_keeps_an_existing_file() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("f");
        std::fs::write(&p, b"keep").unwrap();
        touch_new(&p).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"keep");
        let missing = t.path().join("no/such/f");
        assert!(touch_new(&missing).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn new_folders_and_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let nested = t.path().join("a/b");
        create_dir_all(&nested).unwrap();
        assert_eq!(mode(&t.path().join("a")), DIR_MODE);
        assert_eq!(mode(&nested), DIR_MODE);
        create_dir_all(&nested).unwrap();

        let f = nested.join("f");
        create_file(&f).unwrap();
        assert_eq!(mode(&f), FILE_MODE);
        // An existing world-readable file becomes private when rewritten.
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        create_file(&f).unwrap();
        assert_eq!(mode(&f), FILE_MODE);

        let g = nested.join("g");
        touch_new(&g).unwrap();
        assert_eq!(mode(&g), FILE_MODE);
    }

    #[cfg(unix)]
    #[test]
    fn a_new_wallet_is_private() {
        let t = tempfile::tempdir().unwrap();
        let folder = t.path().join("vault");
        let wallet = crate::Wallet::create(&folder, "TestPassword123", "en").unwrap();
        assert_eq!(mode(&folder), DIR_MODE);
        let db = folder.join(crate::DATABASE_FILENAME);
        assert_eq!(mode(&db), FILE_MODE);
        for sidecar in ["-wal", "-shm"] {
            let p = folder.join(format!("{}{sidecar}", crate::DATABASE_FILENAME));
            if p.exists() {
                assert_eq!(mode(&p), FILE_MODE, "{sidecar}");
            }
        }
        drop(wallet);
    }
}
