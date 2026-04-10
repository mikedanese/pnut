//! Filesystem-based include resolver for seccomp policy files.

use std::path::{Path, PathBuf};

use crate::codegen::{IncludeContext, IncludeResult};
use crate::error::Error;

/// Resolves `#include` directives by reading files from disk.
///
/// - Relative paths resolve against the including file's parent directory
///   (or `base_dir` for top-level includes).
/// - Absolute paths are used directly.
///
/// # Example
///
/// ```rust,no_run
/// use kafel::{CompileOptions, FilesystemResolver};
///
/// let resolver = FilesystemResolver::new("/etc/pnut/policies");
/// let opts = CompileOptions::new()
///     .with_include_resolver(move |name, ctx| resolver.resolve(name, ctx));
/// ```
pub struct FilesystemResolver {
    base_dir: PathBuf,
}

impl FilesystemResolver {
    /// Create a resolver rooted at `base_dir`.
    ///
    /// Typically this is the parent directory of the top-level policy file.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Resolve an include filename to its contents.
    pub fn resolve(&self, filename: &str, ctx: &IncludeContext) -> Result<IncludeResult, Error> {
        let path = Path::new(filename);
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else {
            let dir = ctx
                .parent
                .map(|p| Path::new(p).parent().unwrap_or(self.base_dir.as_path()))
                .unwrap_or(self.base_dir.as_path());
            dir.join(filename)
        };
        let canonical = resolved
            .canonicalize()
            .map_err(|_| Error::IncludeNotFound {
                filename: filename.to_string(),
                span: None,
            })?;
        let contents = std::fs::read_to_string(&canonical).map_err(|_| Error::IncludeNotFound {
            filename: filename.to_string(),
            span: None,
        })?;
        Ok(IncludeResult {
            contents,
            canonical_name: Some(canonical.to_string_lossy().into_owned()),
        })
    }
}
