//! PassMan - A secure password manager written in Rust

pub mod errors;
pub mod models;
pub mod crypto;
pub mod db;

pub use errors::{PassManError, Result};
pub use models::PasswordEntry;
pub use crypto::{generate_password, encrypt_password, decrypt_password};
