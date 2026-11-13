use crate::error::ScaError;
use crate::models::{Package, ScaReport};
use async_trait::async_trait;
use std::path::Path;

/// Trait implemented by lockfile parsers (Cargo.lock, package-lock.json, etc.).
pub trait LockfileParser: Send + Sync {
    /// Returns true if this parser can handle the specified file name/path.
    fn can_parse(&self, path: &Path) -> bool;

    /// Parses the raw string contents of the lockfile into package records.
    fn parse(&self, path: &Path, content: &str) -> Result<Vec<Package>, ScaError>;
}

/// Unified asynchronous interface for running SCA scans.
#[async_trait]
pub trait ScaAnalyzer: Send + Sync {
    /// Scan target workspace or lockfile and return an aggregated report.
    async fn scan(&self, target: &Path) -> Result<ScaReport, ScaError>;
}
