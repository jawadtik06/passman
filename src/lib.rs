//! PassMan - A secure password manager written in Rust
//!
//! This library provides the core functionality for managing encrypted passwords.

// Public modules
pub mod errors;
pub mod models;

// Re-export commonly used types
pub use errors::{PassManError, Result};
pub use models::PasswordEntry;
