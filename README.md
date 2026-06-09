# 🔐 PassMan - Secure Password Manager

A memory-safe, encrypted password manager written in Rust.

## ✨ Features

- 🔒 **AES-256-GCM** authenticated encryption
- 🧂 **Argon2id** password hashing (memory-hard, GPU-resistant)
- 🗄️ **SQLite** database with prepared statements (no injection)
- 📋 **Secure clipboard** with auto-clear
- 🔑 **Cryptographically secure** password generator
- 🦀 **Memory-safe** by Rust's ownership system

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/jawadtik06/passman.git
cd passman
cargo build --release
./target/release/passman