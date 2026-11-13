// Copyright 2026 CyberGuard Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Core trait abstractions for static analysis engines.

use async_trait::async_trait;
use cyberguard_core::{CyberguardError, SarifResult};

use crate::context::ScanContext;

/// Pluggable interface for static analysis scanning engines.
#[async_trait]
pub trait SastAnalyzer: Send + Sync {
    /// Human-readable identifier of the static analyzer.
    fn name(&self) -> &str;

    /// Health check or availability verification for the analyzer.
    fn is_available(&self) -> bool {
        true
    }

    /// Execute static analysis scan across files defined in `ScanContext`.
    async fn analyze(&self, ctx: &ScanContext) -> Result<Vec<SarifResult>, CyberguardError>;
}
