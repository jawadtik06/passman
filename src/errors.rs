//! Error handling module for PassMan
//!
//! Defines custom error types and results for the password manager.

use thiserror::Error;

/// Main error type for PassMan
///
/// This enum represents all possible errors that can occur in the application.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum PassManError {
    /// Cryptography-related errors (encryption, decryption, hashing)
    #[error("Cryptography error: {0}")]
    CryptoError(String),

    /// Database operation errors (SQLite)
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// File I/O errors
    #[error("IO error: {0}")]
    IoError(String),

    /// Wrong master password provided
    #[error("Authentication failed: Wrong master password")]
    AuthenticationFailed,

    /// Vault file doesn't exist (first-time setup needed)
    #[error("Vault not found. Run passman --init first")]
    VaultNotFound,

    /// Failed to decrypt a password
    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    /// Clipboard operation failed
    #[error("Clipboard error: {0}")]
    ClipboardError(String),
}

/// Result type alias for PassMan operations
pub type Result<T> = std::result::Result<T, PassManError>;

impl PassManError {
    /// Returns true if the error is recoverable (user can retry the operation)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            PassManError::AuthenticationFailed
                | PassManError::IoError(_)
                | PassManError::DatabaseError(_)
        )
    }

    /// Returns a user-friendly error message suitable for end users
    pub fn user_message(&self) -> String {
        match self {
            PassManError::CryptoError(_) => {
                "Security error occurred. Check your encryption settings.".to_string()
            }
            PassManError::DatabaseError(_) => {
                "Database error. Try running with --repair flag.".to_string()
            }
            PassManError::IoError(msg) if msg.contains("not found") => {
                "File not found. Run --init to create a new vault.".to_string()
            }
            PassManError::IoError(_) => "File access error. Check permissions.".to_string(),
            PassManError::AuthenticationFailed => {
                "Wrong master password. Please try again.".to_string()
            }
            PassManError::VaultNotFound => "No vault found. Set up a new vault first.".to_string(),
            PassManError::DecryptionError(_) => {
                "Failed to decrypt password. Vault may be corrupted.".to_string()
            }
            PassManError::ClipboardError(_) => {
                "Cannot access clipboard. Check your system settings.".to_string()
            }
        }
    }

    /// Returns the error code for programmatic handling
    pub fn error_code(&self) -> &'static str {
        match self {
            PassManError::CryptoError(_) => "E001",
            PassManError::DatabaseError(_) => "E002",
            PassManError::IoError(_) => "E003",
            PassManError::AuthenticationFailed => "E004",
            PassManError::VaultNotFound => "E005",
            PassManError::DecryptionError(_) => "E006",
            PassManError::ClipboardError(_) => "E007",
        }
    }
}

// Convenience conversions
impl From<std::io::Error> for PassManError {
    fn from(err: std::io::Error) -> Self {
        PassManError::IoError(err.to_string())
    }
}

impl From<rusqlite::Error> for PassManError {
    fn from(err: rusqlite::Error) -> Self {
        PassManError::DatabaseError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_recoverable() {
        // Recoverable errors
        assert!(PassManError::AuthenticationFailed.is_recoverable());
        assert!(PassManError::IoError("error".to_string()).is_recoverable());
        assert!(PassManError::DatabaseError("error".to_string()).is_recoverable());

        // Non-recoverable errors
        assert!(!PassManError::CryptoError("error".to_string()).is_recoverable());
        assert!(!PassManError::DecryptionError("error".to_string()).is_recoverable());
        assert!(!PassManError::VaultNotFound.is_recoverable());
        assert!(!PassManError::ClipboardError("error".to_string()).is_recoverable());
    }

    #[test]
    fn test_user_message() {
        let test_cases = vec![
            (PassManError::AuthenticationFailed, "Wrong master password"),
            (PassManError::VaultNotFound, "No vault found"),
            (
                PassManError::IoError("file not found".to_string()),
                "File not found",
            ),
            (
                PassManError::ClipboardError("error".to_string()),
                "Cannot access clipboard",
            ),
            (
                PassManError::CryptoError("error".to_string()),
                "Security error",
            ),
            (
                PassManError::DecryptionError("error".to_string()),
                "Failed to decrypt",
            ),
        ];

        for (error, expected_phrase) in test_cases {
            assert!(
                error.user_message().contains(expected_phrase),
                "Error: {:?}, Message: {}, Expected: {}",
                error,
                error.user_message(),
                expected_phrase
            );
        }
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(
            PassManError::CryptoError("".to_string()).error_code(),
            "E001"
        );
        assert_eq!(
            PassManError::DatabaseError("".to_string()).error_code(),
            "E002"
        );
        assert_eq!(PassManError::IoError("".to_string()).error_code(), "E003");
        assert_eq!(PassManError::AuthenticationFailed.error_code(), "E004");
        assert_eq!(PassManError::VaultNotFound.error_code(), "E005");
        assert_eq!(
            PassManError::DecryptionError("".to_string()).error_code(),
            "E006"
        );
        assert_eq!(
            PassManError::ClipboardError("".to_string()).error_code(),
            "E007"
        );
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let pass_err: PassManError = io_err.into();

        match pass_err {
            PassManError::IoError(msg) => assert!(msg.contains("missing")),
            _ => panic!("Wrong conversion"),
        }
    }

    #[test]
    fn test_display_formatting() {
        let err = PassManError::CryptoError("test".to_string());
        assert_eq!(format!("{}", err), "Cryptography error: test");

        let err = PassManError::AuthenticationFailed;
        assert_eq!(
            format!("{}", err),
            "Authentication failed: Wrong master password"
        );

        let err = PassManError::VaultNotFound;
        assert_eq!(
            format!("{}", err),
            "Vault not found. Run passman --init first"
        );
    }

    #[test]
    fn test_clone_and_eq() {
        let err1 = PassManError::CryptoError("test".to_string());
        let err2 = err1.clone();

        assert_eq!(err1, err2);
        assert_eq!(format!("{}", err1), format!("{}", err2));
    }
}
