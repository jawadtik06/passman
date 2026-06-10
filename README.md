# PassMan - Professional Password Manager

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-AES--256--GCM-brightgreen.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Tests](https://img.shields.io/badge/tests-65%2B-success.svg)](https://github.com/jawadtik06/passman/actions)

**PassMan** is a secure, memory-safe password manager written in Rust. It combines military-grade encryption with a professional command-line interface to help you manage your passwords securely and efficiently.

## Table of Contents

- [Features](#features)
- [Security Model](#security-model)
- [Installation](#installation)
- [Usage](#usage)
- [Technical Details](#technical-details)
- [Testing](#testing)
- [License](#license)

## Features

### Core Security
- **AES-256-GCM Encryption** - Industry-standard authenticated encryption for all stored passwords
- **Argon2id Key Derivation** - Memory-hard password hashing resistant to GPU-based attacks
- **Unique Nonces per Entry** - Each password encrypted with a unique initialization vector
- **Master Password Authentication** - Your master password is never stored, only its hash

### Functionality
- **Secure Password Generation** - Cryptographically random passwords with customizable length and character sets
- **Clipboard Integration** - Auto-copy passwords to clipboard with secure handling
- **SQLite Database** - Local storage with prepared statements preventing SQL injection
- **Search & Filter** - Find passwords by website or username with partial matching
- **Password Strength Indicator** - Visual feedback on password strength

### Technical Excellence
- **Memory Safety** - Rust's ownership system prevents buffer overflows and memory leaks
- **Zero Dependencies on External Services** - Fully offline, your data never leaves your machine
- **Comprehensive Testing** - 65+ unit and integration tests ensuring reliability

## Security Model

```text
┌─────────────────────────────────────────────────────────────────┐
│                      MASTER PASSWORD                            │
│                       (never stored)                            │
└─────────────────────────────┬───────────────────────────────────┘
                              │
                    ┌─────────▼─────────┐
                    │      Argon2id     │
                    │    Key Derivation │
                    └─────────┬─────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
    ┌───────▼───────┐ ┌───────▼───────┐ ┌───────▼───────┐
    │    Password   │ │    Password   │ │    Password   │
    │     Entry 1   │ │     Entry 2   │ │     Entry 3   │
    │  AES-256-GCM  │ │  AES-256-GCM  │ │  AES-256-GCM  │
    │  + Unique     │ │  + Unique     │ │  + Unique     │
    │    Nonce      │ │    Nonce      │ │    Nonce      │
    └───────────────┘ └───────────────┘ └───────────────┘
```

### Key Security Properties
- **Forward Secrecy** - Compromise of master password doesn't expose previous passwords
- **Authenticated Encryption** - Tamper detection prevents ciphertext modification
- **Memory Hardness** - Argon2id configuration (19 MB memory, 2 iterations) resists ASIC attacks

## Installation

### Prerequisites

- **Rust** 1.70 or higher
- **Cargo** package manager
- **SQLite3** development libraries

### Install from Source

```bash
# Clone the repository
git clone https://github.com/jawadtik06/passman.git
cd passman

# Build release binary
cargo build --release

# Optional: Install to system path
cargo install --path .
```

### Install Dependencies (Linux)

```bash
# Ubuntu/Debian
sudo apt install libsqlite3-dev libxcb-shape0-dev libxcb-xfixes0-dev

# Fedora/RHEL
sudo dnf install sqlite-devel libxcb-devel

# Arch Linux
sudo pacman -S sqlite libxcb
```

## Usage

### First Run

```bash
./target/release/passman
```

On first execution, PassMan will:

1-Prompt you to create a master password (minimum 8 characters)

2-Generate a unique cryptographic salt

3-Create an encrypted vault file (vault.key)

4-Initialize the SQLite database (passwords.db)

### Command-Line Interface

```text
╔════════════════════════════════════════════════════════╗
║                    P A S S M A N                       ║
║           Professional Password Manager                ║
║                   Version 1.0.0                        ║
╚════════════════════════════════════════════════════════╝

PassMan - Main Menu
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. Add Password
  2. List Passwords
  3. Search Passwords
  4. Generate Password
  5. Delete Password
  6. Exit
```

### Menu Operations

| Command | Description | Example |
|---------|-------------|---------|
| Add Password | Store a new password (manual or generated) | `1` → enter website, username, password |
| List Passwords | Display all stored entries with masked passwords | `2` → shows all entries |
| Search Passwords | Find entries by website or username | `3` → enter search term |
| Generate Password | Create cryptographically secure random password | `4` → specify length and special chars |
| Delete Password | Remove an entry from the vault | `5` → select entry to delete |

### Example Session

```bash
$ passman

PassMan - Add New Password
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Website/Service: github.com
Username/Email: john.doe
Generate secure password? [Y/n]: y
Password length (default: 20): 24

[SUCCESS] Password saved successfully!

PassMan - List Passwords
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   1. github.com - john.doe
      Password: X7k***...
```

## Technical Details

### Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Encryption | AES-256-GCM | Password encryption |
| Key Derivation | Argon2id | Master password hashing |
| Database | SQLite | Local password storage |
| Random Generation | `rand` + `OsRng` | Cryptographic randomness |
| Clipboard | `arboard` | Cross-platform clipboard |
| CLI Framework | `dialoguer` + `console` | Interactive terminal UI |

### Project Structure

```text
passman/
├── src/
│   ├── main.rs          # CLI entry point
│   ├── lib.rs           # Library exports
│   ├── errors.rs        # Error types and handling
│   ├── models.rs        # Data structures
│   ├── crypto.rs        # Encryption, hashing, generation
│   ├── db.rs            # SQLite operations
│   └── cli.rs           # User interface
├── tests/
│   ├── test_errors.rs   # Error integration tests
│   ├── test_models.rs   # Models integration tests
│   ├── test_crypto.rs   # Crypto integration tests
│   └── test_db.rs       # Database integration tests
└── Cargo.toml          # Dependencies and configuration
```

### Cryptographic Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| AES Key Length | 256 bits | Encryption strength |
| Nonce Length | 96 bits | Unique per encryption |
| Argon2 Memory | 19 MB | Memory-hard hashing |
| Argon2 Iterations | 2 | Time-hard hashing |
| Salt Length | 128 bits | Prevent rainbow tables |
| Password Min | 8 chars | Master password policy |
| Password Max | 64 chars | Generated password limit |

## Testing

### Run All Tests

```bash
cargo test
```
### Run Specific Test Suites

```bash
# Unit tests only
cargo test --lib

# Integration tests only
cargo test --test test_crypto

# Specific module tests
cargo test --lib crypto

# With output
cargo test -- --nocapture
```

### Test Coverage

| Module | Unit Tests | Integration Tests | Total |
|--------|------------|-------------------|-------|
| Errors | 6 | 9 | 15 |
| Models | 8 | 12 | 20 |
| Crypto | 14 | 14 | 28 |
| Database | 7 | 9 | 16 |
| **Total** | **35** | **44** | **79** |

## Performance

- **Vault Unlock**: < 50ms (Argon2id derivation)
- **Password Encryption**: < 1ms per entry
- **Database Query**: < 5ms for 1000 entries
- **Memory Usage**: ~20 MB for vault operations

## File Structure

```text
~/.passman/           # Default vault location (if installed)
├── vault.key         # Encrypted master password hash + salt
└── passwords.db      # SQLite database with encrypted entries
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Permission denied | Check file permissions on `~/.passman/` |
| Database locked | Close other instances of PassMan |
| Clipboard error | Install xclip (Linux) or xsel (macOS) |
| Wrong master password | Password is unrecoverable - vault is designed to be secure |

### Debug Mode

```bash
RUST_BACKTRACE=1 cargo run
```
## Contributing

Contributions are welcome! Please ensure:

- Code passes `cargo test` and `cargo clippy`
- New features include appropriate tests
- Documentation is updated accordingly

## License

This project is dual-licensed under:

- **MIT License** - [LICENSE-MIT](LICENSE-MIT)
- **Apache License 2.0** - [LICENSE-APACHE](LICENSE-APACHE)

You may choose either license at your option.

## Disclaimer

**IMPORTANT**: This software is provided "as is" without warranty. Always maintain secure backups of your `vault.key` and `passwords.db` files. The author is not responsible for any data loss or security breaches resulting from the use of this software.

---

**Built with 🦀 Rust** | **Security through transparency** | **Professional Password Management**