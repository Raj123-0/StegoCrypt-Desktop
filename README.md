# StegoCrypt: AES-128 Image Steganography

**A fully offline, standalone Python desktop application that securely hides encrypted text messages inside standard image files.**

StegoCrypt combines AES-128 symmetric encryption (via the `Fernet` module) with Least Significant Bit (LSB) steganography, wrapped in a thread-safe `customtkinter` GUI that stays responsive during heavy image-processing workloads.

---

## Table of Contents

- [Core Features](#core-features)
- [Installation & Setup](#installation--setup)
- [How to Use](#how-to-use)
  - [Encoding (Hiding a Message)](#encoding-hiding-a-message)
  - [Decoding (Extracting a Message)](#decoding-extracting-a-message)
- [Supported Formats](#supported-formats)
- [How It Works](#how-it-works)
- [License](#license)

---

## Core Features

| Feature | Description |
|---|---|
| 🔐 **Strong Encryption** | Derives an encryption key from your password using `PBKDF2HMAC` with SHA-256 and 480,000 iterations, appending a randomized 16-byte salt to every payload. |
| 🖼️ **Invisible Data Masking** | Modifies only the least significant bits of the Red, Green, and Blue pixel channels — the hidden payload is invisible to the human eye. |
| 🛡️ **Data Integrity Protection** | Automatically calculates image capacity before encoding and enforces lossless `.png` output, preventing JPEG compression from corrupting the steganographic bits. |
| ⚡ **Thread-Safe Processing** | Heavy bitwise operations run on background daemon threads, keeping the progress bar and UI responsive and never freezing the window. |
| 📴 **Fully Offline** | No network calls — your messages, images, and passwords never leave your machine. |

---

## Installation & Setup

**Requirements:** Python 3.9+

1. Clone the repository:
   ```bash
   git clone https://github.com/Raj123-0/StegoCrypt-Desktop.git
   cd StegoCrypt-Desktop
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python main.py
   ```

---

## How to Use

### Encoding (Hiding a Message)

1. Navigate to the **Encode & Hide** tab.
2. Select a cover image (`.png`, `.jpg`, `.jpeg`, `.bmp`).
3. Type your secret message into the text box and provide a strong encryption password.
4. Click **Encode & Save Image**. The app generates a new `.png` file containing your encrypted, hidden message.

### Decoding (Extracting a Message)

1. Navigate to the **Extract & Decrypt** tab.
2. Select your previously encoded `.png` stego-image.
3. Enter the exact password used during encryption.
4. Click **Extract & Decrypt Message**. If the password is correct and the image data is intact, your original message is displayed.

> ⚠️ **Note:** Always save encoded images as `.png`. Re-saving or converting a stego-image to `.jpg` (or any lossy format) will destroy the hidden data.

---

## Supported Formats

| Stage | Accepted Input | Output |
|---|---|---|
| Encoding | `.png`, `.jpg`, `.jpeg`, `.bmp` | `.png` (lossless, required) |
| Decoding | `.png` (previously encoded) | Decrypted plaintext message |

---

## How It Works

1. **Key Derivation** — Your password and a random 16-byte salt are passed through PBKDF2HMAC (SHA-256, 480,000 iterations) to derive a symmetric key.
2. **Encryption** — The message is encrypted with Fernet (AES-128 in CBC mode with HMAC authentication) using the derived key.
3. **Embedding** — The encrypted bytes are written into the least significant bits of the image's RGB channels.
4. **Output** — The result is saved as a lossless `.png` so every embedded bit survives.

Decoding reverses this process: bits are read from the image, decrypted with a key re-derived from your password and the embedded salt, and the original message is recovered.

---

## License

MIT License 
