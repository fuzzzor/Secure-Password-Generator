# Secure Password Generator v1.4

**Secure Password Generator** is a modern, ultra-compact, and secure application developed in **Rust** using the **Slint** GUI framework. It allows you to generate strong passwords using two distinct methods while providing real-time strength analysis.

## 🚀 Key Features

### 1. Two Generation Modes
*   **Fixed Mode (PSK - Pre-Shared Key):** Generates a deterministic password based on a passphrase. By using the same passphrase and settings, you will always get the same password.
    *   *Technology:* Uses the **PBKDF2** algorithm with **HMAC-SHA512** for maximum security.
*   **Random Mode:** Generates a completely random password.
    *   *Technology:* Uses a cryptographically secure random number generator (CSPRNG).

### 2. Full Customization
*   **Character Types:** Uppercase, lowercase, digits, and special characters.
*   **Custom Special Characters:** Modify the list of allowed symbols to meet specific requirements.
*   **Adjustable Length:** From 3 up to 128 characters.

### 3. Security and User Experience
*   **Entropy Indicator:** Calculates password complexity in bits in real-time and displays a security level (Weak, Medium, Strong).
*   **Secure Clipboard:** The "Copy" button places the password in memory and **automatically clears it after 15 seconds** to prevent accidental leaks.
*   **Passphrase Masking:** Toggle the visibility of your passphrase using the eye icon.
*   **Ultra-Compact Interface:** Optimized to occupy minimal screen space (620px height) while remaining perfectly readable.
*   **Smart Centering:** Advanced display scaling (DPI) management on Windows to ensure the window is always perfectly centered, even on 4K screens.

## 🛠 Installation and Build

### Prerequisites
*   [Rust](https://www.rust-lang.org/) (latest stable version)
*   A C++ compiler (required for Slint dependencies)

### Build and Run
```bash
# Clone the repository
git clone <repository-url>
cd GenPass-Rust

# Build and run
cargo run --release
```

## 💻 Technical Stack
*   **Language:** Rust 2021
*   **UI Framework:** Slint 1.9+
*   **Cryptography:** `pbkdf2`, `hmac`, `sha2`
*   **System:** `windows-sys` for native Windows integrations (DPI, resolution)

## 📄 License
This software is a freeware coded in Rust. You are free to use and distribute it without limitations.

---
*Created by Stéphane Dudez (2006-2026)*
