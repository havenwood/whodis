use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = whodis::Cli::parse();
    whodis::run(cli).await
}
