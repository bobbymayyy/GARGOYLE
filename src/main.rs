use clap::{Parser, Subcommand};
use gargoyle::config::Config;
use gargoyle::runtime;
use gargoyle::Result;
use std::path::PathBuf;
use std::process::ExitCode;

#[cfg(unix)]
const DEFAULT_CONFIG_PATH: &str = "/etc/gargoyle/gargoyle.toml";
#[cfg(windows)]
const DEFAULT_CONFIG_PATH: &str = r"C:\ProgramData\GARGOYLE\gargoyle.toml";
#[cfg(not(any(unix, windows)))]
const DEFAULT_CONFIG_PATH: &str = "gargoyle.toml";

#[derive(Debug, Parser)]
#[command(name = "gargoyle")]
#[command(version, about = "A hardened cross-platform telemetry and detection watchdog")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the GARGOYLE agent.
    Run {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Parse and validate a configuration file.
    Validate {
        #[arg(short, long, default_value = DEFAULT_CONFIG_PATH)]
        config: PathBuf,
    },
    /// Print the built-in default configuration for this operating system.
    PrintDefaultConfig,
    /// Print the event JSON Schema.
    PrintEventSchema,
}

fn execute(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run { config } => {
            if !config.exists() {
                eprintln!(
                    "GARGOYLE: {} not found; using platform defaults",
                    config.display()
                );
            }
            runtime::run(Config::load_or_default(&config)?)
        }
        Command::Validate { config } => {
            Config::load(&config)?;
            println!("configuration is valid: {}", config.display());
            Ok(())
        }
        Command::PrintDefaultConfig => {
            print!("{}", Config::default().to_pretty_toml()?);
            Ok(())
        }
        Command::PrintEventSchema => {
            print!("{}", include_str!("../schemas/event.schema.json"));
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("GARGOYLE error: {error}");
            ExitCode::FAILURE
        }
    }
}
