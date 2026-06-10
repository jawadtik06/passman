//! Integration tests for PassMan error handling

use passman::errors::{PassManError, Result};

fn sample_errors() -> Vec<PassManError> {
    vec![
        PassManError::CryptoError("Invalid key".to_string()),
        PassManError::DatabaseError("Connection failed".to_string()),
        PassManError::IoError("File not found".to_string()),
        PassManError::AuthenticationFailed,
        PassManError::VaultNotFound,
        PassManError::DecryptionError("Wrong nonce".to_string()),
        PassManError::ClipboardError("X11 error".to_string()),
    ]
}

// Display & Formatting Tests
#[test]
fn error_display_formats_correctly() {
    let cases = vec![
        (
            PassManError::CryptoError("Invalid key".to_string()),
            "Cryptography error: Invalid key",
        ),
        (
            PassManError::DatabaseError("Connection failed".to_string()),
            "Database error: Connection failed",
        ),
        (
            PassManError::IoError("File not found".to_string()),
            "IO error: File not found",
        ),
        (
            PassManError::AuthenticationFailed,
            "Authentication failed: Wrong master password",
        ),
        (
            PassManError::VaultNotFound,
            "Vault not found. Run passman --init first",
        ),
        (
            PassManError::DecryptionError("Wrong nonce".to_string()),
            "Decryption failed: Wrong nonce",
        ),
        (
            PassManError::ClipboardError("X11 error".to_string()),
            "Clipboard error: X11 error",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(format!("{}", error), expected);
    }
}

#[test]
fn debug_format_includes_variant_and_data() {
    let error = PassManError::CryptoError("test_secret".to_string());
    let debug_str = format!("{:?}", error);

    assert!(debug_str.contains("CryptoError"));
    assert!(debug_str.contains("test_secret"));
}

// Result Type Alias Tests
#[test]
fn result_alias_works() {
    fn success() -> Result<i32> {
        Ok(42)
    }
    fn failure() -> Result<i32> {
        Err(PassManError::AuthenticationFailed)
    }

    assert_eq!(success().unwrap(), 42);
    assert!(failure().is_err());
}

// Error Conversion Tests
#[test]
fn io_error_automatically_converts() {
    fn operation() -> Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing file",
        ))?
    }

    match operation() {
        Err(PassManError::IoError(msg)) => assert!(msg.contains("missing file")),
        _ => panic!("Expected IoError conversion"),
    }
}

#[test]
fn from_trait_converts_io_error() {
    let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
    let pass_error: PassManError = io_error.into();

    match pass_error {
        PassManError::IoError(msg) => assert!(msg.contains("access denied")),
        _ => panic!("Expected IoError"),
    }
}

// Error Method Tests
#[test]
fn is_recoverable_classifies_correctly() {
    assert!(PassManError::AuthenticationFailed.is_recoverable());
    assert!(PassManError::IoError("error".to_string()).is_recoverable());
    assert!(PassManError::DatabaseError("error".to_string()).is_recoverable());

    assert!(!PassManError::CryptoError("error".to_string()).is_recoverable());
    assert!(!PassManError::DecryptionError("error".to_string()).is_recoverable());
    assert!(!PassManError::VaultNotFound.is_recoverable());
}

#[test]
fn user_message_returns_friendly_messages() {
    let cases = vec![
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
    ];

    for (error, expected) in cases {
        assert!(error.user_message().contains(expected));
    }
}

#[test]
fn vault_not_found_behavior() {
    let error = PassManError::VaultNotFound;

    assert_eq!(
        format!("{}", error),
        "Vault not found. Run passman --init first"
    );
    assert_eq!(
        error.user_message(),
        "No vault found. Set up a new vault first."
    );
    assert!(!error.is_recoverable());
}

// Collection Tests
#[test]
fn errors_can_be_stored_in_collections() {
    let errors = sample_errors();
    assert_eq!(errors.len(), 7);
}

#[test]
fn errors_can_be_pattern_matched() {
    match PassManError::CryptoError("A".to_string()) {
        PassManError::CryptoError(msg) => assert_eq!(msg, "A"),
        _ => panic!("Pattern match failed"),
    }
}

#[test]
fn errors_can_be_wrapped() {
    let original = PassManError::CryptoError("Root cause".to_string());
    let wrapped = PassManError::DatabaseError(format!("Wrapper: {}", original));
    let msg = format!("{}", wrapped);

    assert!(msg.contains("Wrapper"));
    assert!(msg.contains("Root cause"));
}

// Equality Tests
#[test]
fn identical_errors_are_equal() {
    let err1 = PassManError::CryptoError("same".to_string());
    let err2 = PassManError::CryptoError("same".to_string());
    assert_eq!(format!("{}", err1), format!("{}", err2));
}

#[test]
fn different_errors_are_not_equal() {
    let err1 = PassManError::CryptoError("one".to_string());
    let err2 = PassManError::CryptoError("two".to_string());
    assert_ne!(format!("{}", err1), format!("{}", err2));
}

#[test]
fn error_implements_traits() {
    let error = PassManError::CryptoError("test".to_string());
    assert!(!format!("{}", error).is_empty());
    assert!(!format!("{:?}", error).is_empty());
}
