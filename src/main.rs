//! PassMan CLI - Professional Password Manager

use passman::Cli;

fn main() {
    println!(
        "{}",
        console::style("╔════════════════════════════════════════════════════════╗").cyan()
    );
    println!(
        "{}",
        console::style("║                    P A S S M A N                       ║")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        console::style("║            Professional Password Manager               ║").cyan()
    );
    println!(
        "{}",
        console::style("║                   Version 1.0.0                        ║").cyan()
    );
    println!(
        "{}",
        console::style("╚════════════════════════════════════════════════════════╝").cyan()
    );
    println!();

    if let Err(e) = Cli::new().and_then(|mut cli| cli.run()) {
        eprintln!("\n{} {}", console::style("[ERROR]").red().bold(), e);
        std::process::exit(1);
    }
}
