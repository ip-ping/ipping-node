use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use ipping_node::connection::{self, Settings};
use ipping_node::enroll::{self, Details};
use ipping_node::state::{Identity, StateDir};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "ipping-node", version, about = "Measurement node for ipping")]
struct Cli {
    /// Where the node keeps its identity and credential (created with private permissions)
    #[arg(
        long,
        env = "IPPING_NODE_STATE_DIR",
        default_value = "/var/lib/ipping-node",
        global = true
    )]
    state_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register this node with a backend using a single-use enrollment token
    Enroll(EnrollArgs),
    /// Connect to the backend and run measurements (enrolls first when a token is provided)
    Run(RunArgs),
}

#[derive(Args, Clone)]
struct EnrollArgs {
    /// Backend address, for example https://ping.example.com
    #[arg(long, env = "IPPING_NODE_SERVER")]
    server: String,
    /// Enrollment token created in the admin page
    #[arg(long, env = "IPPING_NODE_ENROLL_TOKEN", hide_env_values = true)]
    token: String,
    /// Display name for this node
    #[arg(long, env = "IPPING_NODE_NAME")]
    name: Option<String>,
    /// Two-letter country code
    #[arg(long, env = "IPPING_NODE_COUNTRY")]
    country: Option<String>,
    #[arg(long, env = "IPPING_NODE_REGION")]
    region: Option<String>,
    #[arg(long, env = "IPPING_NODE_CITY")]
    city: Option<String>,
    #[arg(long, env = "IPPING_NODE_LATITUDE", allow_hyphen_values = true)]
    latitude: Option<f64>,
    #[arg(long, env = "IPPING_NODE_LONGITUDE", allow_hyphen_values = true)]
    longitude: Option<f64>,
    #[arg(long, env = "IPPING_NODE_PROVIDER")]
    provider: Option<String>,
    #[arg(long, env = "IPPING_NODE_ASN")]
    asn: Option<u32>,
}

#[derive(Args)]
struct RunArgs {
    /// Most tasks this node will run at the same time
    #[arg(long, env = "IPPING_NODE_MAX_TASKS", default_value_t = 8)]
    max_tasks: usize,
    /// Backend address; overrides the one saved at enrollment
    #[arg(long, env = "IPPING_NODE_SERVER")]
    server: Option<String>,
    /// Optional enrollment, used only when the node has no credential yet
    #[command(flatten)]
    enroll: OptionalEnroll,
}

#[derive(Args)]
struct OptionalEnroll {
    #[arg(
        long = "enroll-token",
        env = "IPPING_NODE_ENROLL_TOKEN",
        hide_env_values = true
    )]
    token: Option<String>,
    #[arg(long, env = "IPPING_NODE_NAME")]
    name: Option<String>,
    #[arg(long, env = "IPPING_NODE_COUNTRY")]
    country: Option<String>,
    #[arg(long, env = "IPPING_NODE_REGION")]
    region: Option<String>,
    #[arg(long, env = "IPPING_NODE_CITY")]
    city: Option<String>,
    #[arg(long, env = "IPPING_NODE_LATITUDE", allow_hyphen_values = true)]
    latitude: Option<f64>,
    #[arg(long, env = "IPPING_NODE_LONGITUDE", allow_hyphen_values = true)]
    longitude: Option<f64>,
    #[arg(long, env = "IPPING_NODE_PROVIDER")]
    provider: Option<String>,
    #[arg(long, env = "IPPING_NODE_ASN")]
    asn: Option<u32>,
}

/// An empty value (`IPPING_NODE_COUNTRY=` in an .env file) means "not set", not "set to nothing".
fn set(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn default_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|h| !h.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|h| h.trim().to_owned())
        })
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "ipping-node".to_owned())
}

async fn do_enroll(state: &StateDir, args: EnrollArgs) -> Result<(), String> {
    let details = Details {
        name: set(args.name).unwrap_or_else(default_name),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        country: set(args.country),
        region: set(args.region),
        city: set(args.city),
        latitude: args.latitude,
        longitude: args.longitude,
        provider: set(args.provider),
        asn: args.asn,
    };
    let server = args.server.trim().trim_end_matches('/').to_owned();
    let (server_for_call, token) = (server.clone(), args.token);
    let enrolled =
        tokio::task::spawn_blocking(move || enroll::enroll(&server_for_call, &token, &details))
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
    state
        .save(
            &Identity {
                server,
                node_id: enrolled.node_id.clone(),
            },
            &enrolled.credential,
        )
        .map_err(|e| {
            format!(
                "could not save the credential in {}: {e}",
                state.path().display()
            )
        })?;
    println!(
        "Enrolled as node {} (status: {}).",
        enrolled.node_id, enrolled.status
    );
    if enrolled.status == "pending" {
        println!("An administrator must approve it in the admin page before it receives work.");
    }
    Ok(())
}

async fn do_run(state: StateDir, args: RunArgs) -> Result<(), String> {
    let mut loaded = state
        .load()
        .map_err(|e| format!("cannot read {}: {e}", state.path().display()))?;
    if loaded.is_none() {
        let (Some(token), Some(server)) =
            (set(args.enroll.token.clone()), set(args.server.clone()))
        else {
            return Err(format!(
                "this node is not enrolled yet. Run `ipping-node enroll --server <url> --token <token>`, \
                 or set IPPING_NODE_SERVER and IPPING_NODE_ENROLL_TOKEN. (state dir: {})",
                state.path().display()
            ));
        };
        let e = args.enroll;
        do_enroll(
            &state,
            EnrollArgs {
                server,
                token,
                name: e.name,
                country: e.country,
                region: e.region,
                city: e.city,
                latitude: e.latitude,
                longitude: e.longitude,
                provider: e.provider,
                asn: e.asn,
            },
        )
        .await?;
        loaded = state.load().map_err(|e| e.to_string())?;
    }
    let loaded = loaded.ok_or("enrollment did not produce a credential")?;
    let settings = Settings {
        server: set(args.server).unwrap_or(loaded.identity.server),
        credential: loaded.credential,
        max_concurrent_tasks: args.max_tasks,
    };

    let shutdown = CancellationToken::new();
    tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            wait_for_stop_signal().await;
            tracing::info!("stopping");
            shutdown.cancel();
        }
    });
    tracing::info!(version = env!("CARGO_PKG_VERSION"), node = %loaded.identity.node_id, "starting");
    connection::run(settings, shutdown).await;
    Ok(())
}

async fn wait_for_stop_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("IPPING_NODE_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .init();

    let state = StateDir::new(cli.state_dir);
    let result = match cli.command {
        Command::Enroll(args) => do_enroll(&state, args).await,
        Command::Run(args) => do_run(state, args).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}
