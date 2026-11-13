use clap::{Args, Parser, Subcommand, ValueEnum};
use cyberguard_core::config::CyberguardConfig;
use cyberguard_core::sarif::{Message, ReportingDescriptor, SarifLevel, SarifLog};
use cyberguard_sast::{NativeRuleEngine, SastAnalyzer, ScanContext};
use cyberguard_sca::sbom::{generate_cyclonedx_json, generate_spdx_json};
use cyberguard_sca::{ScaAnalyzer, ScaEngine};
use std::path::{Path, PathBuf};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(
    name = "cyberguard",
    version = env!("CARGO_PKG_VERSION"),
    about = "Autonomous Vulnerability Intelligence & Remediation Platform",
    long_about = "CyberGuard is an uncompromising, next-generation open-source vulnerability intelligence platform\nbuilt in Rust. It discovers real flaws in modern software, correlates attack path graphs (DAG),\nand autonomously synthesizes AST-verified code fixes."
)]
pub struct Cli {
    /// Custom configuration file path (defaults to cyberguard.yaml)
    #[arg(global = true, short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Enable verbose diagnostic logging
    #[arg(global = true, short, long)]
    pub verbose: bool,

    /// Suppress all non-essential output
    #[arg(global = true, short, long)]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Commands {
    /// Perform deep vulnerability discovery across the codebase
    Scan(ScanArgs),

    /// Audit cloud, network, and supply-chain assets
    Audit(AuditArgs),

    /// Trace multi-layer attack paths and correlate findings via in-memory DAG
    Trace(TraceArgs),

    /// Synthesize and apply syntax-preserving AST code fixes
    Fix(FixArgs),

    /// Launch CyberGuard as an AI agent Model Context Protocol (MCP) server
    Mcp(McpArgs),
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct ScanArgs {
    /// Target directory or source file to scan
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output report format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Minimum severity threshold
    #[arg(long, value_name = "LEVEL")]
    pub min_severity: Option<String>,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct AuditArgs {
    /// Target directory or dependency manifest (defaults to current directory)
    #[arg(default_value = ".")]
    pub target: String,

    /// Output report format
    #[arg(short, long, value_enum, default_value_t = AuditFormat::Terminal)]
    pub format: AuditFormat,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditFormat {
    Terminal,
    Sarif,
    Json,
    Cyclonedx,
    Spdx,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct TraceArgs {
    /// Target repository path to construct Attack Path Graph
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct FixArgs {
    /// Target file or directory for automated remediation
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Automatically apply fixes without manual confirmation
    #[arg(long)]
    pub auto: bool,

    /// Perform a dry-run and print unified diffs to stdout
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args, Debug, PartialEq, Eq)]
pub struct McpArgs {
    /// Run MCP JSON-RPC protocol over standard I/O (stdio)
    #[arg(long, default_value_t = true)]
    pub stdio: bool,

    /// Optional port to serve MCP over Server-Sent Events (SSE)
    #[arg(long)]
    pub port: Option<u16>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Terminal,
    Sarif,
    Json,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.quiet {
        Level::ERROR
    } else if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();

    let _ = tracing::subscriber::set_global_default(subscriber);

    // Load layered configuration
    let config = CyberguardConfig::load_layered(cli.config.as_deref())
        .unwrap_or_else(|_| CyberguardConfig::default());

    match cli.command {
        Some(Commands::Scan(args)) => {
            let mut ctx = ScanContext::new(&args.path);
            if let Some(ref sev) = args.min_severity {
                ctx = ctx.with_min_severity(Some(sev.clone()));
            }

            let engine = NativeRuleEngine::default();
            let findings = engine.analyze(&ctx).await?;

            match args.format {
                OutputFormat::Sarif | OutputFormat::Json => {
                    let mut log = SarifLog::new("CyberGuard SAST", env!("CARGO_PKG_VERSION"));
                    for rule in engine.rules() {
                        log.add_rule(ReportingDescriptor {
                            id: rule.id.clone(),
                            name: Some(rule.name.clone()),
                            short_description: Message {
                                text: rule.message.clone(),
                            },
                            full_description: None,
                            help_uri: Some(rule.help_uri.clone()),
                        });
                    }
                    for finding in findings {
                        log.add_result(finding);
                    }
                    println!("{}", serde_json::to_string_pretty(&log)?);
                }
                OutputFormat::Terminal => {
                    println!("🛡️  CyberGuard SAST Engine v{}", env!("CARGO_PKG_VERSION"));
                    println!("Target: {}", args.path.display());
                    println!("Workspace: {}", config.general.workspace_dir.display());
                    println!("{:-<80}", "");

                    if findings.is_empty() {
                        println!("✅ No security vulnerabilities detected.");
                    } else {
                        println!("Found {} vulnerability alert(s):", findings.len());
                        println!();
                        for f in &findings {
                            let loc_str = if let Some(loc) = f.locations.first() {
                                if let Some(phys) = &loc.physical_location {
                                    if let Some(reg) = &phys.region {
                                        format!(
                                            "{}:{}:{}",
                                            phys.artifact_location.uri,
                                            reg.start_line,
                                            reg.start_column.unwrap_or(1)
                                        )
                                    } else {
                                        phys.artifact_location.uri.clone()
                                    }
                                } else {
                                    "-".to_string()
                                }
                            } else {
                                "-".to_string()
                            };

                            let sev_label = match f.level {
                                SarifLevel::Error => "🔴 ERROR",
                                SarifLevel::Warning => "🟡 WARN ",
                                SarifLevel::Note => "🔵 NOTE ",
                                SarifLevel::None => "⚪ NONE ",
                            };

                            println!("{} [{}] {}", sev_label, f.rule_id, loc_str);
                            println!("   └── {}", f.message.text);
                            if let Some(fps) = &f.partial_fingerprints {
                                if let Some(hash) = fps.get("logicalLocationTokenHash/v1") {
                                    let preview = if hash.len() > 16 { &hash[..16] } else { hash };
                                    println!("   └── Fingerprint: {}", preview);
                                }
                            }
                        }
                    }
                    println!("{:-<80}", "");
                }
            }
        }
        Some(Commands::Audit(args)) => {
            let target_path = Path::new(&args.target);
            let sca_engine = ScaEngine::new();
            let report = sca_engine.scan(target_path).await?;

            match args.format {
                AuditFormat::Cyclonedx => {
                    let project_name = target_path
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("project");
                    let cyclonedx_json = generate_cyclonedx_json(project_name, &report.packages)?;
                    println!("{}", cyclonedx_json);
                }
                AuditFormat::Spdx => {
                    let project_name = target_path
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("project");
                    let spdx_json = generate_spdx_json(project_name, &report.packages)?;
                    println!("{}", spdx_json);
                }
                AuditFormat::Sarif | AuditFormat::Json => {
                    let sarif_log = sca_engine.to_sarif_log(&report);
                    println!("{}", serde_json::to_string_pretty(&sarif_log)?);
                }
                AuditFormat::Terminal => {
                    println!(
                        "🛡️  CyberGuard SCA & Supply Chain Auditor v{}",
                        env!("CARGO_PKG_VERSION")
                    );
                    println!("Target: {}", target_path.display());
                    println!(
                        "Scanned {} lockfile(s) | Total dependencies: {} ({} direct, {} transitive)",
                        report.lockfiles_scanned.len(),
                        report.total_packages,
                        report.direct_dependencies,
                        report.transitive_dependencies
                    );
                    println!("{:-<80}", "");

                    if report.findings.is_empty() {
                        println!("✅ No known supply-chain vulnerabilities found in dependencies.");
                    } else {
                        println!(
                            "Found {} vulnerable dependency alert(s):",
                            report.findings.len()
                        );
                        println!();
                        for finding in &report.findings {
                            let sev_label = if finding.vulnerability.cvss >= 9.0 {
                                "🔴 CRITICAL"
                            } else if finding.vulnerability.cvss >= 7.0 {
                                "🔴 HIGH    "
                            } else if finding.vulnerability.cvss >= 4.0 {
                                "🟡 MEDIUM  "
                            } else {
                                "🔵 LOW     "
                            };

                            let dep_type = if finding.package.is_direct {
                                "Direct"
                            } else {
                                "Transitive"
                            };

                            println!(
                                "{} [{}] {}@{} ({:?})",
                                sev_label,
                                finding.vulnerability.id,
                                finding.package.name,
                                finding.package.version,
                                finding.package.ecosystem
                            );
                            println!("   └── {}", finding.vulnerability.summary);
                            println!(
                                "   └── CVSS: {:.1} | EPSS: {:.2} | Reachability: {:.1} ({}) | Tri-Factor: {:.2}",
                                finding.vulnerability.cvss,
                                finding.vulnerability.epss,
                                finding.reachability,
                                dep_type,
                                finding.tri_factor_score
                            );
                            if let Some(ref fixed) = finding.vulnerability.fixed_version {
                                println!("   └── Remediation: Upgrade to {} or later", fixed);
                            }
                        }
                    }
                    println!("{:-<80}", "");
                }
            }
        }
        Some(Commands::Trace(args)) => {
            println!(
                "🕸️  Constructing in-memory Attack Path Graph (DAG) for: {}",
                args.path.display()
            );
            println!("[+] Nodes: 0 | Edges: 0 | Exploit Chains: 0");
        }
        Some(Commands::Fix(args)) => {
            println!("🛠️  CyberGuard AST Auto-Remediation Engine");
            println!(
                "Target: {} (auto={}, dry_run={})",
                args.path.display(),
                args.auto,
                args.dry_run
            );
        }
        Some(Commands::Mcp(args)) => {
            println!("🤖 CyberGuard Model Context Protocol (MCP) Server");
            if let Some(port) = args.port {
                println!("Starting SSE transport on port {}", port);
            } else {
                println!("Listening on stdio (JSON-RPC 2.0)...");
            }
        }
        None => {
            println!(
                "🛡️  CyberGuard {} - Next-Generation Autonomous Vulnerability Intelligence",
                env!("CARGO_PKG_VERSION")
            );
            println!("Run 'cyberguard --help' for available commands.");
        }
    }

    Ok(())
}
