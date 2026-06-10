//! PassMan - A secure password manager written in Rust

pub mod cli;
pub mod crypto;
pub mod db;
pub mod errors;
pub mod models;

pub use cli::Cli;
pub use crypto::{decrypt_password, encrypt_password, generate_password};
pub use db::Database;
pub use errors::{PassManError, Result};
pub use models::PasswordEntry;
