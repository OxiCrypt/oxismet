use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// A file written to a `.tmp` sibling and renamed over the target only on [`commit`].
/// If dropped without committing, the temporary file is removed, so a failed run
/// never leaves a truncated output behind or clobbers an existing file.
///
/// [`commit`]: AtomicFile::commit
pub struct AtomicFile {
    file: File,
    tmp_path: PathBuf,
    final_path: PathBuf,
    committed: bool,
}

impl AtomicFile {
    pub fn create(path: &Path, msg: &str) -> Result<Self, ExitCode> {
        let tmp_path = path.with_added_extension("tmp");
        let file = File::create(&tmp_path).map_err(|e| {
            eprintln!("{msg}");
            eprintln!("Root Error: {e}");
            ExitCode::FAILURE
        })?;
        Ok(Self {
            file,
            tmp_path,
            final_path: path.to_path_buf(),
            committed: false,
        })
    }

    /// Syncs the written data to disk, then renames it over the target path.
    pub fn commit(mut self) -> Result<(), ExitCode> {
        self.file
            .sync_all()
            .and_then(|()| fs::rename(&self.tmp_path, &self.final_path))
            .map_err(|e| {
                eprintln!(
                    "Error: Failed to finalize output file {}: {e}",
                    self.final_path.display()
                );
                ExitCode::FAILURE
            })?;
        self.committed = true;
        Ok(())
    }
}

impl Write for AtomicFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for AtomicFile {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}
