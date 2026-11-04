//! sops-ls: a language server for SOPS-encrypted files.

mod rules;
mod scan;
mod server;
mod sops;
mod text;

use tower_lsp_server::{LspService, Server};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("sops-ls {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some(sops::EDITOR_SUBCOMMAND) => std::process::exit(sops::editor_main(&args[1..])),
        Some("--stdio") | None => {}
        Some(other) => {
            eprintln!("sops-ls: unknown argument {other:?} (usage: sops-ls [--stdio|--version])");
            std::process::exit(2);
        }
    }
    let (service, socket) = LspService::new(server::Backend::new);
    Server::new(tokio::io::stdin(), tokio::io::stdout(), socket).serve(service).await;
}
