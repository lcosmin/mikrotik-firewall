use anyhow::Result;
use clap::{self, Parser};
use std::path::PathBuf;
use tracing::{error, info};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Parser, Debug)]
#[command(name = "mikrotik-firewall", version, about, long_about)]
struct Args {
    /// Render firewall
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    render: bool,

    /// Build firewall
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    build: bool,

    /// Debug
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    debug: bool,

    /// Firewall path
    #[arg(short, long, value_name = "FIREWALL")]
    firewall: PathBuf,

    /// Output
    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,
}

mod firewall;

fn start(args: Args) -> Result<()> {
    // let args = Args {
    //     render: false,
    //     build: true,
    //     firewall: PathBuf::from_str("firewalls/fargate")?,
    //     output: PathBuf::from_str("foo")?,
    // };

    // Create the firewall
    let fw = firewall::loader::load(&args.firewall).map_err(|e| {
        let msg = format!("load firewall: {:?}", &e.root_cause());
        e.context(msg)
    })?;

    //fw.test()?;

    //return Ok(());

    if args.build {
        info!("building firewall");

        if args.debug {
            fw.dump();
        }

        info!("optimizing...");
        let optimized = fw.optimize()?;

        let serialized = optimized.serialize()?;

        info!("{}", serialized.join("\n"));
    }
    Ok(())
}

fn main() -> Result<()> {
    let _the_env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "your_app=debug,tower_http=debug,axum::rejection=trace".into());

    let f = fmt::layer()
        .with_level(true)
        //.with_line_number(true)
        .with_target(true);
    //.with_thread_ids(true);

    tracing_subscriber::registry()
        //.with(the_env_filter)
        //.with(ForestLayer::default())
        .with(f)
        .init();

    // Set the subscriber as the global default
    // tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    //let _ts = span!(Level::TRACE, "application configuration");

    let args = Args::parse();

    match start(args) {
        Ok(_) => Ok(()),
        Err(e) => {
            error!("{}", &e);
            Ok(())
        }
    }
}
