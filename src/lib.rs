//! PassMan - A secure password manager written in Rust
//! 
//! This library provides the core functionality for managing encrypted passwords.

// Public modules
pub mod errors;
pub mod models;
pub mod crypto;

// Re-export commonly used types
pub use errors::{PassManError, Result};
pub use models::PasswordEntry;
pub use crypto::{generate_password, encrypt_password, decrypt_password};
