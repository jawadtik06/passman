// Import our library
use passman::errors::PassManError;

// We'll use Result later, but for now let's keep it commented
// use passman::errors::Result;

fn main() {
    println!("🔐 PassMan - Secure Password Manager");
    println!("✅ Step 1 complete - Error types are working!\n");

    // Demonstrate error handling
    demonstrate_errors();
}

fn demonstrate_errors() {
    // Test creating and displaying errors
    let errors = vec![
        PassManError::CryptoError("Invalid key length".to_string()),
        PassManError::AuthenticationFailed,
        PassManError::VaultNotFound,
    ];

    for error in errors {
        println!("  • {}", error);
        println!("    User-friendly: {}", error.user_message());
        println!("    Recoverable: {}", error.is_recoverable());
        println!();
    }

    // Test the From conversion
    let io_error = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Access denied");
    let pass_error: PassManError = io_error.into();
    println!("  • Converted IO error: {}", pass_error);

    // Example of using Result (commented for now)
    // fn test_function() -> Result<()> {
    //     Ok(())
    // }
}
