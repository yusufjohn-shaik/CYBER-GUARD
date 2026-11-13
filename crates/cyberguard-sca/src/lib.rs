#![deny(unsafe_code)]

//! # CyberGuard SCA
//!
//! Software Composition Analysis (SCA) and Supply Chain Security Engine.
//! Provides lockfile parsing (Cargo, npm), standard CycloneDX and SPDX SBOM generation,
//! and semver-based OSV vulnerability matching.

pub mod db;
pub mod engine;
pub mod error;
pub mod models;
pub mod parsers;
pub mod sbom;
pub mod traits;

pub use db::VulnerabilityDatabase;
pub use engine::ScaEngine;
pub use error::ScaError;
pub use models::{Ecosystem, Package, ScaFinding, ScaReport, Vulnerability};
pub use traits::{LockfileParser, ScaAnalyzer};
