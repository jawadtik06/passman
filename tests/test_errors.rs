//! Integration tests for PassMan error handling
//!
//! These tests verify the public API of our error module works correctly.
//! They import from the compiled library to test the real implementation.

use passman::errors::{PassManError, Result};

// ============================================================================
// Test Helpers
// ============================================================================

/// Creates a collection of all error variants for comprehensive testing
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

// ============================================================================
// Display & Formatting Tests
// ============================================================================

#[test]
fn error_display_formats_correctly() {
    let test_cases = vec![
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

    for (error, expected) in test_cases {
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

// ============================================================================
// Result Type Alias Tests
// ============================================================================

#[test]
fn result_alias_works_for_success() {
    fn success() -> Result<i32> {
        Ok(42)
    }

    assert_eq!(success().unwrap(), 42);
}

#[test]
fn result_alias_works_for_error() {
    fn failure() -> Result<i32> {
        Err(PassManError::AuthenticationFailed)
    }

    let result = failure();
    assert!(result.is_err());

    match result {
        Err(PassManError::AuthenticationFailed) => (),
        _ => panic!("Expected AuthenticationFailed error"),
    }
}

// ============================================================================
// Error Conversion Tests
// ============================================================================

#[test]
fn io_error_automatically_converts() {
    fn operation_with_io_error() -> Result<()> {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "missing file");
        Err(io_error)?
    }

    let result = operation_with_io_error();
    assert!(result.is_err());

    match result {
        Err(PassManError::IoError(msg)) => assert!(msg.contains("missing file")),
        _ => panic!("Expected IoError conversion"),
    }
}

#[test]
fn from_trait_converts_io_error_explicitly() {
    let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
    let pass_error: PassManError = io_error.into();

    match pass_error {
        PassManError::IoError(msg) => assert!(msg.contains("access denied")),
        _ => panic!("Expected IoError"),
    }
}

// ============================================================================
// Error Method Tests
// ============================================================================

#[test]
fn is_recoverable_classifies_errors_correctly() {
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
fn user_message_returns_friendly_messages() {
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
        (
            PassManError::DatabaseError("error".to_string()),
            "Database error",
        ),
    ];

    for (error, expected_phrase) in test_cases {
        assert!(
            error.user_message().contains(expected_phrase),
            "Error: {:?}\nMessage: {}\nExpected: {}",
            error,
            error.user_message(),
            expected_phrase
        );
    }
}

#[test]
fn vault_not_found_error_has_correct_behavior() {
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

// ============================================================================
// Collection & Container Tests
// ============================================================================

#[test]
fn errors_can_be_stored_in_collections() {
    let errors = sample_errors();
    assert_eq!(errors.len(), 7);

    // Verify all variants are present
    let variant_types: Vec<String> = errors.iter().map(|e| format!("{:?}", e)).collect();
    assert!(variant_types.iter().any(|s| s.contains("CryptoError")));
    assert!(variant_types.iter().any(|s| s.contains("DatabaseError")));
    assert!(variant_types.iter().any(|s| s.contains("IoError")));
    assert!(
        variant_types
            .iter()
            .any(|s| s.contains("AuthenticationFailed"))
    );
    assert!(variant_types.iter().any(|s| s.contains("VaultNotFound")));
}

#[test]
fn errors_can_be_pattern_matched() {
    let error = PassManError::CryptoError("A".to_string());

    match error {
        PassManError::CryptoError(msg) => assert_eq!(msg, "A"),
        _ => panic!("Pattern match failed"),
    }
}

#[test]
fn errors_can_be_wrapped_in_other_errors() {
    let original = PassManError::CryptoError("Root cause".to_string());
    let wrapped = PassManError::DatabaseError(format!("Wrapper: {}", original));

    let wrapped_msg = format!("{}", wrapped);
    assert!(wrapped_msg.contains("Wrapper"));
    assert!(wrapped_msg.contains("Root cause"));
}

// ============================================================================
// Equality & Trait Tests
// ============================================================================

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
fn error_implements_required_traits() {
    let error = PassManError::CryptoError("test".to_string());

    // Display trait
    assert!(!format!("{}", error).is_empty());

    // Debug trait
    assert!(!format!("{:?}", error).is_empty());

    // Send + Sync (compiler check - these are auto-implemented)
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PassManError>();
}
