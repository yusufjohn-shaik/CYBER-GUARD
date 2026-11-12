use clap::Parser;
use std::path::PathBuf;

// We will test Clap derive command parsing directly
#[derive(Parser, Debug)]
#[command(name = "cyberguard", version = "0.3.0")]
struct Cli {
    #[arg(global = true, short, long)]
    config: Option<PathBuf>,

    #[arg(global = true, short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(clap::Subcommand, Debug, PartialEq, Eq)]
enum Commands {
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(short, long)]
        format: Option<String>,
    },
    Audit {
        target: String,
    },
    Trace {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    Fix {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        auto: bool,
    },
    Mcp {
        #[arg(long, default_value_t = true)]
        stdio: bool,
    },
}

#[test]
fn test_cli_scan_subcommand_defaults() {
    let args = Cli::parse_from(["cyberguard", "scan"]);
    assert_eq!(
        args.command,
        Some(Commands::Scan {
            path: PathBuf::from("."),
            format: None
        })
    );
}

#[test]
fn test_cli_scan_with_custom_path_and_format() {
    let args = Cli::parse_from(["cyberguard", "scan", "/src/app", "--format", "sarif"]);
    assert_eq!(
        args.command,
        Some(Commands::Scan {
            path: PathBuf::from("/src/app"),
            format: Some("sarif".to_string())
        })
    );
}

#[test]
fn test_cli_fix_subcommand_auto_flag() {
    let args = Cli::parse_from(["cyberguard", "fix", "--auto", "src/"]);
    assert_eq!(
        args.command,
        Some(Commands::Fix {
            path: PathBuf::from("src/"),
            auto: true
        })
    );
}

#[test]
fn test_cli_mcp_subcommand() {
    let args = Cli::parse_from(["cyberguard", "mcp"]);
    assert_eq!(args.command, Some(Commands::Mcp { stdio: true }));
}
