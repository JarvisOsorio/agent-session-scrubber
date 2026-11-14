use agentscrub::cli::commands::run;
use agentscrub::cli::Cli;
use agentscrub::errors::ExitCode;
use clap::Parser;
use tracing_subscriber::EnvFilter;

fn main() {
    let cli = Cli::parse();
    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_writer(std::io::stderr)
        .try_init();

    match run(cli) {
        Ok(code) => std::process::exit(code.as_i32()),
        Err(err) => {
            eprintln!("error: {err}");
            let code = err.exit_code();
            std::process::exit(if code == ExitCode::Ok {
                ExitCode::General.as_i32()
            } else {
                code.as_i32()
            });
        }
    }
}
