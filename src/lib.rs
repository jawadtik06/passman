//! PassMan - A secure password manager written in Rust
//!
//! This library provides the core functionality for managing encrypted passwords.

// Public modules (exposed to external crates and integration tests)
pub mod errors;
// pub mod crypto;  // Will add in Step 3
// pub mod db;      // Will add in Step 4
// pub mod models;  // Will add in Step 2

// Re-export commonly used types
pub use errors::{PassManError, Result};
