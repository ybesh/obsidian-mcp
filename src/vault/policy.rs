//! Vault path permissions, evaluated after path resolution.

use std::path::Path;
use std::sync::Arc;

use crate::error::{VaultError, VaultResult};

use super::exclude::{self, ExcludeSet};
use super::path::ResolvedPath;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Denied,
    ReadOnly,
    ReadWrite,
}

impl Permission {
    pub fn can_read(self) -> bool {
        matches!(self, Self::ReadOnly | Self::ReadWrite)
    }
}

/// Permission predicates over canonical, already-resolved vault paths.
///
/// Exclusions and hidden components always deny access. When no writable
/// patterns are configured, visible paths remain writable for backward
/// compatibility. Otherwise the resolved path must match the writable set.
pub struct AccessPolicy {
    denied: Arc<ExcludeSet>,
    writable: Option<ExcludeSet>,
}

impl AccessPolicy {
    pub fn new(denied: Arc<ExcludeSet>, write_patterns: Vec<String>) -> VaultResult<Self> {
        let writable = if write_patterns.is_empty() {
            None
        } else {
            Some(ExcludeSet::build(write_patterns)?)
        };
        Ok(Self { denied, writable })
    }

    pub fn permission(&self, resolved: &ResolvedPath) -> Permission {
        if self.is_denied(&resolved.relative) {
            return Permission::Denied;
        }

        match &self.writable {
            None => Permission::ReadWrite,
            Some(writable) if writable.is_excluded(&resolved.relative) => Permission::ReadWrite,
            Some(_) => Permission::ReadOnly,
        }
    }

    pub fn authorize_read(&self, resolved: &ResolvedPath) -> VaultResult<()> {
        match self.permission(resolved) {
            permission if permission.can_read() => Ok(()),
            Permission::Denied => Err(VaultError::PathExcluded(resolved.relative.clone())),
            Permission::ReadOnly | Permission::ReadWrite => unreachable!(),
        }
    }

    pub fn authorize_write(&self, resolved: &ResolvedPath) -> VaultResult<()> {
        match self.permission(resolved) {
            Permission::ReadWrite => Ok(()),
            Permission::ReadOnly => Err(VaultError::PathReadOnly(resolved.relative.clone())),
            Permission::Denied => Err(VaultError::PathExcluded(resolved.relative.clone())),
        }
    }

    fn is_denied(&self, path: &Path) -> bool {
        !exclude::is_visible_path(path)
            || self.denied.is_excluded(path)
            || self
                .denied
                .is_excluded(&path.join("__obsidian_mcp_policy_probe__"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn resolved(relative: &str) -> ResolvedPath {
        ResolvedPath {
            relative: PathBuf::from(relative),
            absolute: PathBuf::from("/vault").join(relative),
        }
    }

    fn policy(denied: &[&str], writable: &[&str]) -> AccessPolicy {
        AccessPolicy::new(
            Arc::new(
                ExcludeSet::build(denied.iter().map(|value| (*value).to_string()).collect())
                    .unwrap(),
            ),
            writable.iter().map(|value| (*value).to_string()).collect(),
        )
        .unwrap()
    }

    #[test]
    fn read_write_permission_includes_read() {
        let permission = policy(&[], &[]).permission(&resolved("note.md"));
        assert_eq!(permission, Permission::ReadWrite);
        assert!(permission.can_read());
    }

    #[test]
    fn visible_path_outside_write_patterns_is_read_only() {
        let permission = policy(&[], &["editable.md"]).permission(&resolved("readable.md"));
        assert_eq!(permission, Permission::ReadOnly);
        assert!(permission.can_read());
    }

    #[test]
    fn exact_write_pattern_grants_read_write() {
        let permission = policy(&[], &["editable.md"]).permission(&resolved("editable.md"));
        assert_eq!(permission, Permission::ReadWrite);
    }

    #[test]
    fn denial_wins_over_write_pattern() {
        let permission = policy(&["private/**"], &["private/editable.md"])
            .permission(&resolved("private/editable.md"));
        assert_eq!(permission, Permission::Denied);
    }

    #[test]
    fn denied_subtree_also_denies_its_directory_entry() {
        let permission = policy(&["Archive/**"], &[]).permission(&resolved("Archive"));
        assert_eq!(permission, Permission::Denied);
    }
}
