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

//! # CyberGuard SAST Engine
//!
//! High-performance, in-process Static Application Security Testing (SAST) engine.
//! Provides zero-dependency regular expression matching with linear-time $O(n)$ search guarantees,
//! smart directory traversal with cycle detection, and standard OASIS SARIF v2.1.0 telemetry export.

pub mod context;
pub mod engine;
pub mod rules;
pub mod traits;
pub mod walker;

pub use context::ScanContext;
pub use engine::NativeRuleEngine;
pub use rules::{SastRule, SeverityThreshold};
pub use traits::SastAnalyzer;
pub use walker::collect_source_files;
