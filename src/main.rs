//! PassMan CLI - Secure Password Manager

use passman::Cli;

fn main() {
    println!("{}", console::style("🔐 PassMan v0.1.0").bold().cyan());
    
    if let Err(e) = Cli::new().and_then(|mut cli| cli.run()) {
        eprintln!("{} {}", console::style("Error:").red().bold(), e);
        std::process::exit(1);
    }
}
