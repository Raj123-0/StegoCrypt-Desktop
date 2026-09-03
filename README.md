# StegoCrypt: AES-128 Image Steganography

**A fully offline Python desktop app (and CLI) that hides encrypted messages or files inside standard image files.**

StegoCrypt combines AES-128 symmetric encryption (via Fernet) with Least Significant Bit (LSB) steganography. The `customtkinter` GUI stays responsive during image work by running encode/decode on a background thread.

---

## Table of Contents

- [Core Features](#core-features)
- [Installation & Setup](#installation--setup)
- [How to Use](#how-to-use)
  - [Encoding (Hiding a Message)](#encoding-hiding-a-message)
  - [Decoding (Extracting a Message)](#decoding-extracting-a-message)
  - [Command line](#command-line)
- [Supported Formats](#supported-formats)
- [How It Works](#how-it-works)
- [Tests](#tests)
- [License](#license)

---

## Core Features

| Feature | Description |
|---|---|
| 🔐 **Strong Encryption** | Derives a key from your password using PBKDF2-HMAC-SHA256 (480,000 iterations) and a random 16-byte salt. |
| 🖼️ **Invisible Data Masking** | Writes only the least significant bits of the R, G, and B channels. |
| 📁 **Messages and Files** | Hide typed text, load a text file, or embed an arbitrary file and recover it later. |
| 🛡️ **Integrity-Friendly Output** | Checks image capacity before embedding and always writes lossless `.png` so JPEG recompression cannot wipe the LSBs. |
| 🔄 **Backward Compatible** | Still extracts payloads created by the original delimiter-based format. |
| ⚡ **Responsive UI** | Encode/decode run on a background thread, with progress, image preview, capacity estimate, password confirmation, and copy/save of results. |
| 📴 **Fully Offline** | No network calls. Messages, images, and passwords stay on your machine. |

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
   python StegoCrypt.py
   ```
   `python main.py` works the same way.

---

## How to Use

### Encoding (Hiding a Message)

1. Open the **Encode & Hide** tab.
2. Select a cover image (`.png`, `.jpg`, `.jpeg`, `.bmp`, `.webp`, `.tif`).
3. Type a secret message, load a text file, or choose **Hide a File…**.
4. Enter and confirm a strong encryption password.
5. Click **Encode & Save Image**. The app writes a new `.png` containing the encrypted payload.

The capacity line under the image estimates whether the cover is large enough *before* you wait on encryption.

### Decoding (Extracting a Message)

1. Open the **Extract & Decrypt** tab.
2. Select the encoded `.png`.
3. Enter the password used during encryption.
4. Click **Extract & Decrypt Message**. Copy the text, or use **Save to File** for text or recovered files.

> ⚠️ **Note:** Always keep encoded images as `.png`. Re-saving or converting a stego-image to `.jpg` (or any lossy format) will destroy the hidden data.

### Command line

```bash
python StegoCrypt.py encode cover.png -o hidden.png -m "secret text" -p yourpassword
python StegoCrypt.py encode cover.png -o hidden.png --file notes.zip -p yourpassword
python StegoCrypt.py decode hidden.png -p yourpassword
python StegoCrypt.py decode hidden.png -p yourpassword -o recovered.zip
```

If you omit `-p`, the password is requested with a hidden prompt.

---

## Supported Formats

| Stage | Accepted Input | Output |
|---|---|---|
| Encoding | `.png`, `.jpg`, `.jpeg`, `.bmp`, `.webp`, `.tif`, `.tiff` | `.png` (lossless, required) |
| Decoding | `.png` (previously encoded) | Decrypted text or a recovered file |

---

## How It Works

1. **Packing** — Text or file bytes are wrapped in a small inner header (payload type, and filename when hiding a file).
2. **Key Derivation** — Your password and a random 16-byte salt go through PBKDF2-HMAC-SHA256 (480,000 iterations).
3. **Encryption** — The inner payload is encrypted with Fernet (AES-128 in CBC mode plus HMAC).
4. **Container** — A `SGC1` header stores version, flags, and ciphertext length so extraction does not scan for a delimiter.
5. **Embedding** — Those bytes are written into RGB least-significant bits and saved as PNG.

Decoding reverses the steps. Images produced by older StegoCrypt builds (delimiter `====END====` after the ciphertext) are still detected and decrypted.

---

## Tests

```bash
python -m unittest discover -s tests
```

---

## License

MIT License
