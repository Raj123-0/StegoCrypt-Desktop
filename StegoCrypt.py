"""
StegoCrypt — AES-128 encryption (Fernet) + LSB image steganography.

Usage:
    python StegoCrypt.py
    python StegoCrypt.py encode COVER.png -o OUT.png -m "secret" -p PASSWORD
    python StegoCrypt.py encode COVER.png -o OUT.png --file secret.bin -p PASSWORD
    python StegoCrypt.py decode STEGO.png -p PASSWORD
    python StegoCrypt.py decode STEGO.png -p PASSWORD -o recovered.bin
"""

from __future__ import annotations

import argparse
import base64
import getpass
import os
import sys
import threading
from pathlib import Path
from typing import Callable, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- Constants ---

KDF_ITERATIONS = 480_000
SALT_SIZE = 16
HEADER_MAGIC = b"SGC1"
HEADER_VERSION = 1
HEADER_SIZE = 10  # magic(4) + version(1) + flags(1) + length(4)
FLAG_FILE = 0x01
LEGACY_DELIMITER = b"====END===="
INNER_TEXT = 0x00
INNER_FILE = 0x01


ProgressCallback = Callable[[float], None]


# --- Cryptography ---


class CryptoProcessor:
    """AES encryption via Fernet, with PBKDF2-HMAC-SHA256 key derivation."""

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derive key.
        
        Args:
            password:
            salt:
        
        Returns:
            The computed result
        
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        """Return salt || Fernet(ciphertext)."""
        salt = os.urandom(SALT_SIZE)
        key = CryptoProcessor._derive_key(password, salt)
        ciphertext = Fernet(key).encrypt(data)
        return salt + ciphertext

    @staticmethod
    def decrypt(payload: bytes, password: str) -> bytes:
        """Decrypt.
        
        Args:
            payload (list):
            password:
        
        Returns:
            The computed result
        
        """
        if len(payload) < SALT_SIZE:
            raise ValueError("Corrupted data: payload is too short.")

        salt = payload[:SALT_SIZE]
        ciphertext = payload[SALT_SIZE:]
        key = CryptoProcessor._derive_key(password, salt)

        try:
            return Fernet(key).decrypt(ciphertext)
        except InvalidToken as exc:
            raise ValueError("Incorrect password or corrupted image data.") from exc


# --- Payload packing ---


def pack_inner_text(text: str) -> bytes:
    """Pack inner text.
    
    Args:
        text:
    
    Returns:
        The computed result
    
    """
    return bytes([INNER_TEXT]) + text.encode("utf-8")


def pack_inner_file(filename: str, content: bytes) -> bytes:
    """Pack inner file.
    
    Args:
        filename:
        content:
    
    Returns:
        The computed result
    
    """
    name = Path(filename).name.encode("utf-8")
    if len(name) > 65535:
        raise ValueError("Filename is too long to embed.")
    return bytes([INNER_FILE]) + len(name).to_bytes(2, "big") + name + content


def unpack_inner(data: bytes) -> tuple[str, Optional[str], bytes]:
    """Return (kind, filename_or_none, payload_bytes). kind is 'text' or 'file'."""
    if not data:
        raise ValueError("Corrupted data: empty payload.")

    kind = data[0]
    if kind == INNER_TEXT:
        return "text", None, data[1:]
    if kind == INNER_FILE:
        if len(data) < 3:
            raise ValueError("Corrupted data: incomplete file header.")
        name_len = int.from_bytes(data[1:3], "big")
        end = 3 + name_len
        if len(data) < end:
            raise ValueError("Corrupted data: incomplete filename.")
        name = data[3:end].decode("utf-8", errors="replace")
        return "file", name, data[end:]
    raise ValueError("Unknown payload type. This image may use an unsupported format.")


def build_container(encrypted: bytes, is_file: bool) -> bytes:
    """Create container.
    
    Args:
        encrypted (list):
        is_file:
    
    Returns:
        The computed result
    
    """
    flags = FLAG_FILE if is_file else 0
    return (
        HEADER_MAGIC
        + bytes([HEADER_VERSION, flags])
        + len(encrypted).to_bytes(4, "big")
        + encrypted
    )


def estimate_embedded_bytes(plaintext_len: int) -> int:
    """Conservative upper bound of container size after Fernet encoding."""
    fernet_overhead = 64
    expanded = int((plaintext_len + fernet_overhead) * 1.4) + SALT_SIZE + 16
    return HEADER_SIZE + expanded


def image_capacity_bytes(width: int, height: int) -> int:
    """Image capacity bytes.
    
    Args:
        width:
        height:
    
    Returns:
        The computed result
    
    """
    return (width * height * 3) // 8


# --- LSB helpers ---


def _embed_bytes(raw: bytearray, data: bytes, progress_callback: Optional[ProgressCallback] = None) -> None:
    """Embed bytes.
    
    Args:
        raw (list):
        data (list):
        progress_callback:
    
    """
    total_bits = len(data) * 8
    if total_bits > len(raw):
        raise ValueError(
            f"Image is too small! Max capacity: {len(raw) // 8} bytes. Needed: {len(data)} bytes."
        )

    update_interval = max(1, len(data) // 100)
    bit_index = 0
    for offset, byte in enumerate(data):
        for shift in range(7, -1, -1):
            raw[bit_index] = (raw[bit_index] & 0xFE) | ((byte >> shift) & 1)
            bit_index += 1
        if progress_callback and (offset % update_interval == 0 or offset + 1 == len(data)):
            progress_callback((offset + 1) / len(data) * 0.9)


def _extract_bytes_from_raw(raw: bytes, start_bit: int, count: int) -> bytes:
    """Extract bytes from raw.
    
    Args:
        raw:
        start_bit:
        count:
    
    Returns:
        The computed result
    
    """
    out = bytearray(count)
    idx = start_bit
    for i in range(count):
        value = 0
        for _ in range(8):
            value = (value << 1) | (raw[idx] & 1)
            idx += 1
        out[i] = value
    return bytes(out)


def _open_rgb(image_path: str):
    """Open rgb.
    
    Args:
        image_path:
    
    Returns:
        The computed result
    
    """
    from PIL import Image

    img = Image.open(image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")
    return img


# --- Steganography ---


class StegoProcessor:
    """LSB encode/decode of encrypted payloads inside RGB images."""

    @staticmethod
    def encode(
        image_path: str,
        data: bytes,
        password: str,
        output_path: str,
        is_file: bool = False,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        """Encode.
        
        Args:
            image_path:
            data (list):
            password:
            output_path:
            is_file (bool):
            progress_callback:
        
        """
        from PIL import Image

        img = _open_rgb(image_path)
        raw = bytearray(img.tobytes())
        capacity = len(raw) // 8

        needed_estimate = estimate_embedded_bytes(len(data))
        if needed_estimate > capacity:
            raise ValueError(
                f"Image is too small! Max capacity: {capacity} bytes. "
                f"Needed (estimate): {needed_estimate} bytes."
            )

        encrypted = CryptoProcessor.encrypt(data, password)
        container = build_container(encrypted, is_file=is_file)
        if len(container) > capacity:
            raise ValueError(
                f"Image is too small! Max capacity: {capacity} bytes. Needed: {len(container)} bytes."
            )

        _embed_bytes(raw, container, progress_callback)

        if progress_callback:
            progress_callback(0.9)

        encoded = Image.frombytes("RGB", img.size, bytes(raw))
        output = Path(output_path)
        if output.suffix.lower() != ".png":
            output = output.with_suffix(".png")
        encoded.save(output, format="PNG")

        if progress_callback:
            progress_callback(1.0)

    @staticmethod
    def encode_text(
        image_path: str,
        text: str,
        password: str,
        output_path: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        """Encode text.
        
        Args:
            image_path:
            text:
            password:
            output_path:
            progress_callback:
        
        """
        StegoProcessor.encode(
            image_path,
            pack_inner_text(text),
            password,
            output_path,
            is_file=False,
            progress_callback=progress_callback,
        )

    @staticmethod
    def encode_file(
        image_path: str,
        file_path: str,
        password: str,
        output_path: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        """Encode file.
        
        Args:
            image_path:
            file_path:
            password:
            output_path:
            progress_callback:
        
        """
        content = Path(file_path).read_bytes()
        inner = pack_inner_file(file_path, content)
        StegoProcessor.encode(
            image_path,
            inner,
            password,
            output_path,
            is_file=True,
            progress_callback=progress_callback,
        )

    @staticmethod
    def decode(image_path: str, password: str, progress_callback: Optional[ProgressCallback] = None) -> dict:
        """
        Returns {"kind": "text"|"file"|"legacy_text", "text": str|None, "filename": str|None, "data": bytes}.
        """
        img = _open_rgb(image_path)
        raw = img.tobytes()
        if len(raw) < HEADER_SIZE * 8:
            raise ValueError("Image is too small to contain hidden data.")

        if progress_callback:
            progress_callback(0.15)

        header = _extract_bytes_from_raw(raw, 0, HEADER_SIZE)
        if header[:
            4] == HEADER_MAGIC:
            version = header[4]
            if version != HEADER_VERSION:
                raise ValueError(f"Unsupported StegoCrypt version: {version}.")
            length = int.from_bytes(header[6:10], "big")
            available = len(raw) // 8 - HEADER_SIZE
            if length < 0 or length > available:
                raise ValueError("No hidden data found, or the image has been altered/compressed.")
            if progress_callback:
                progress_callback(0.45)
            encrypted = _extract_bytes_from_raw(raw, HEADER_SIZE * 8, length)
            if progress_callback:
                progress_callback(0.7)
            inner = CryptoProcessor.decrypt(encrypted, password)
            kind, filename, payload = unpack_inner(inner)
            if progress_callback:
                progress_callback(1.0)
            if kind == "text":
                return {
                    "kind": "text",
                    "text": payload.decode("utf-8"),
                    "filename": None,
                    "data": payload,
                }
            return {
                "kind": "file",
                "text": None,
                "filename": filename,
                "data": payload,
            }

        if progress_callback:
            progress_callback(0.3)
        return StegoProcessor._decode_legacy(raw, password, progress_callback)

    @staticmethod
    def _decode_legacy(raw: bytes, password: str, progress_callback: Optional[ProgressCallback] = None) -> dict:
        """Decode legacy.
        
        Args:
            raw (list):
            password:
            progress_callback:
        
        Returns:
            dict: Result of type dict
        
        """
        extracted = bytearray()
        current_byte = 0
        bit_count = 0
        delim_len = len(LEGACY_DELIMITER)
        total = len(raw)

        for i, channel in enumerate(raw):
            current_byte = (current_byte << 1) | (channel & 1)
            bit_count += 1
            if bit_count == 8:
                extracted.append(current_byte)
                current_byte = 0
                bit_count = 0
                if len(extracted) >= delim_len and extracted[-delim_len:
                    ] == LEGACY_DELIMITER:
                    payload = bytes(extracted[:-delim_len])
                    plaintext = CryptoProcessor.decrypt(payload, password)
                    if progress_callback:
                        progress_callback(1.0)
                    return {
                        "kind": "legacy_text",
                        "text": plaintext.decode("utf-8"),
                        "filename": None,
                        "data": plaintext,
                    }
            if progress_callback and i % max(1, total // 50) == 0:
                progress_callback(0.3 + 0.6 * (i / total))

        raise ValueError("No hidden data found, or the image has been altered/compressed.")


# --- GUI ---


def _password_strength(password: str) -> tuple[str, str]:
    """Password strength.
    
    Args:
        password (list):
    
    Returns:
        tuple: Result of type tuple
    
    """
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.islower() for c in password) and any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1

    if not password:
        return "Enter a password", "gray"
    if score <= 1:
        return "Strength: weak", "#e74c3c"
    if score <= 3:
        return "Strength: okay", "#f39c12"
    return "Strength: strong", "#27ae60"


class StegoApp:
    """customtkinter desktop UI. Imported lazily so CLI use does not require a display."""

    def __init__(self) -> None:
        """Init.
        
        """
        import customtkinter as ctk
        from PIL import Image

        self.ctk = ctk
        self._pil_image = Image

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.root = ctk.CTk()
        self.root.title("StegoCrypt")
        self.root.geometry("820x720")
        self.root.minsize(720, 640)

        self.encode_img_path: Optional[str] = None
        self.decode_img_path: Optional[str] = None
        self.encode_file_path: Optional[str] = None
        self._last_dir = os.path.expanduser("~")
        self._decode_result: Optional[dict] = None
        self._encode_preview_image = None
        self._decode_preview_image = None

        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_tabs()

    def _build_header(self) -> None:
        """Create header.
        
        """
        ctk = self.ctk
        header = ctk.CTkFrame(self.root, fg_color="transparent")
        header.grid(row=0, column=0, padx=20, pady=(16, 0), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="StegoCrypt",
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            header,
            text="Hide encrypted messages and files inside lossless PNG images.",
            text_color="gray",
        ).grid(row=1, column=0, sticky="w")

        self.appearance = ctk.CTkSegmentedButton(
            header,
            values=["System", "Dark", "Light"],
            command=self._on_appearance,
        )
        self.appearance.set("System")
        self.appearance.grid(row=0, column=1, rowspan=2, sticky="e")

    def _on_appearance(self, value: str) -> None:
        """On appearance.
        
        Args:
            value:
        
        """
        self.ctk.set_appearance_mode(value)

    def _build_tabs(self) -> None:
        """Create tabs.
        
        """
        ctk = self.ctk
        self.tabview = ctk.CTkTabview(self.root)
        self.tabview.grid(row=1, column=0, padx=20, pady=16, sticky="nsew")
        self.tabview.add("Encode & Hide")
        self.tabview.add("Extract & Decrypt")
        self._setup_encode_tab()
        self._setup_decode_tab()

    def _setup_encode_tab(self) -> None:
        """Setup encode tab.
        
        """
        ctk = self.ctk
        tab = self.tabview.tab("Encode & Hide")
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(3, weight=1)

        self.btn_select_encode_img = ctk.CTkButton(tab, text="Select Cover Image", command=self.select_encode_image)
        self.btn_select_encode_img.grid(row=0, column=0, padx=16, pady=(16, 8), sticky="w")

        self.lbl_encode_img = ctk.CTkLabel(tab, text="No image selected", text_color="gray", anchor="w")
        self.lbl_encode_img.grid(row=0, column=1, padx=16, pady=(16, 8), sticky="ew")

        self.encode_preview = ctk.CTkLabel(tab, text="")
        self.encode_preview.grid(row=0, column=2, rowspan=2, padx=16, pady=(16, 8), sticky="e")

        self.lbl_capacity = ctk.CTkLabel(tab, text="Capacity: —", text_color="gray", anchor="w")
        self.lbl_capacity.grid(row=1, column=0, columnspan=2, padx=16, pady=(0, 8), sticky="w")

        ctk.CTkLabel(tab, text="Secret Message:").grid(row=2, column=0, padx=16, pady=(8, 0), sticky="w")
        payload_btns = ctk.CTkFrame(tab, fg_color="transparent")
        payload_btns.grid(row=2, column=1, columnspan=2, padx=16, pady=(8, 0), sticky="e")
        self.btn_load_text = ctk.CTkButton(payload_btns, text="Load Text File", width=120, command=self.load_text_file)
        self.btn_load_text.pack(side="left", padx=4)
        self.btn_hide_file = ctk.CTkButton(payload_btns, text="Hide a File…", width=120, command=self.choose_hide_file)
        self.btn_hide_file.pack(side="left", padx=4)
        self.btn_reset_payload = ctk.CTkButton(payload_btns, text="Clear", width=70, command=self.reset_payload)
        self.btn_reset_payload.pack(side="left", padx=4)

        self.txt_secret = ctk.CTkTextbox(tab, height=180)
        self.txt_secret.grid(row=3, column=0, columnspan=3, padx=16, pady=8, sticky="nsew")
        self.txt_secret.bind("<KeyRelease>", self._refresh_capacity)

        pass_row = ctk.CTkFrame(tab, fg_color="transparent")
        pass_row.grid(row=4, column=0, columnspan=3, padx=16, pady=4, sticky="ew")
        pass_row.grid_columnconfigure(0, weight=1)
        pass_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(pass_row, text="Encryption Password:").grid(row=0, column=0, sticky="w")
        self.ent_encode_pass = ctk.CTkEntry(pass_row, show="*", placeholder_text="Enter a strong password")
        self.ent_encode_pass.grid(row=1, column=0, padx=(0, 8), pady=4, sticky="ew")
        self.ent_encode_pass.bind("<KeyRelease>", self._on_password_change)

        ctk.CTkLabel(pass_row, text="Confirm Password:").grid(row=0, column=1, sticky="w")
        self.ent_encode_pass2 = ctk.CTkEntry(pass_row, show="*", placeholder_text="Re-enter password")
        self.ent_encode_pass2.grid(row=1, column=1, padx=(8, 0), pady=4, sticky="ew")

        self.show_encode_pass = ctk.CTkCheckBox(pass_row, text="Show password", command=self._toggle_encode_password)
        self.show_encode_pass.grid(row=2, column=0, pady=(0, 4), sticky="w")
        self.lbl_strength = ctk.CTkLabel(pass_row, text="Enter a password", text_color="gray")
        self.lbl_strength.grid(row=2, column=1, pady=(0, 4), sticky="e")

        self.btn_encode = ctk.CTkButton(
            tab,
            text="Encode & Save Image",
            command=self.process_encode,
            fg_color="#27ae60",
            hover_color="#219653",
        )
        self.btn_encode.grid(row=5, column=0, columnspan=3, padx=16, pady=(12, 8))

        self.encode_progress = ctk.CTkProgressBar(tab)
        self.encode_progress.grid(row=6, column=0, columnspan=3, padx=16, pady=(0, 16), sticky="ew")
        self.encode_progress.set(0)

    def _setup_decode_tab(self) -> None:
        """Setup decode tab.
        
        """
        ctk = self.ctk
        tab = self.tabview.tab("Extract & Decrypt")
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(5, weight=1)

        self.btn_select_decode_img = ctk.CTkButton(tab, text="Select Stego Image", command=self.select_decode_image)
        self.btn_select_decode_img.grid(row=0, column=0, padx=16, pady=(16, 8), sticky="w")

        self.lbl_decode_img = ctk.CTkLabel(tab, text="No image selected", text_color="gray", anchor="w")
        self.lbl_decode_img.grid(row=0, column=1, padx=16, pady=(16, 8), sticky="ew")

        self.decode_preview = ctk.CTkLabel(tab, text="")
        self.decode_preview.grid(row=0, column=2, rowspan=2, padx=16, pady=(16, 8), sticky="e")

        ctk.CTkLabel(tab, text="Decryption Password:").grid(row=1, column=0, padx=16, pady=(8, 0), sticky="w")

        pass_row = ctk.CTkFrame(tab, fg_color="transparent")
        pass_row.grid(row=2, column=0, columnspan=2, padx=16, pady=8, sticky="ew")
        pass_row.grid_columnconfigure(0, weight=1)

        self.ent_decode_pass = ctk.CTkEntry(pass_row, show="*", placeholder_text="Enter decryption password")
        self.ent_decode_pass.grid(row=0, column=0, sticky="ew")
        self.show_decode_pass = ctk.CTkCheckBox(pass_row, text="Show", command=self._toggle_decode_password, width=70)
        self.show_decode_pass.grid(row=0, column=1, padx=(8, 0))

        self.btn_decode = ctk.CTkButton(tab, text="Extract & Decrypt Message", command=self.process_decode)
        self.btn_decode.grid(row=3, column=0, columnspan=3, padx=16, pady=12)

        self.decode_progress = ctk.CTkProgressBar(tab)
        self.decode_progress.grid(row=4, column=0, columnspan=3, padx=16, pady=(0, 8), sticky="ew")
        self.decode_progress.set(0)

        ctk.CTkLabel(tab, text="Extracted Message:").grid(row=5, column=0, padx=16, pady=(8, 0), sticky="nw")

        actions = ctk.CTkFrame(tab, fg_color="transparent")
        actions.grid(row=5, column=1, columnspan=2, padx=16, pady=(8, 0), sticky="e")
        self.btn_copy = ctk.CTkButton(actions, text="Copy", width=80, command=self.copy_extracted, state="disabled")
        self.btn_copy.pack(side="left", padx=4)
        self.btn_save_extracted = ctk.CTkButton(
            actions, text="Save to File", width=110, command=self.save_extracted, state="disabled"
        )
        self.btn_save_extracted.pack(side="left", padx=4)
        self.btn_clear_extracted = ctk.CTkButton(
            actions, text="Clear", width=80, command=self.clear_extracted, state="disabled"
        )
        self.btn_clear_extracted.pack(side="left", padx=4)

        self.txt_extracted = ctk.CTkTextbox(tab, height=180, state="disabled")
        self.txt_extracted.grid(row=6, column=0, columnspan=3, padx=16, pady=8, sticky="nsew")
        tab.grid_rowconfigure(6, weight=1)

        self.lbl_decode_status = ctk.CTkLabel(tab, text="", text_color="gray")
        self.lbl_decode_status.grid(row=7, column=0, columnspan=3, padx=16, pady=(0, 12), sticky="w")

    def _image_filetypes(self) -> list:
        """Image filetypes.
        
        Returns:
            list: Result of type list
        
        """
        return [
            ("Image files", "*.png *.jpg *.jpeg *.bmp *.webp *.tif *.tiff"),
            ("PNG", "*.png"),
            ("JPEG", "*.jpg *.jpeg"),
            ("All files", "*.*"),
        ]

    def _thumbnail(self, path: str):
        """Thumbnail.
        
        Args:
            path:
        
        Returns:
            The computed result
        
        """
        img = self._pil_image.open(path)
        img = img.convert("RGB")
        img.thumbnail((128, 128))
        return self.ctk.CTkImage(light_image=img, dark_image=img, size=img.size)

    def _set_preview(self, which: str, path: str) -> None:
        """Set preview.
        
        Args:
            which:
            path:
        
        """
        try:
            preview = self._thumbnail(path)
        except Exception:
            preview = None
        if which == "encode":
            self._encode_preview_image = preview
            self.encode_preview.configure(image=preview, text="" if preview else "")
        else:
            self._decode_preview_image = preview
            self.decode_preview.configure(image=preview, text="" if preview else "")

    def _refresh_capacity(self, _event=None) -> None:
        """Refresh capacity.
        
        Args:
            _event:
        
        """
        if not self.encode_img_path:
            self.lbl_capacity.configure(text="Capacity: —")
            return
        try:
            with self._pil_image.open(self.encode_img_path) as img:
                capacity = image_capacity_bytes(*img.size)
        except Exception:
            self.lbl_capacity.configure(text="Capacity: unable to read image")
            return

        if self.encode_file_path:
            size = Path(self.encode_file_path).stat().st_size + 64
            used = estimate_embedded_bytes(size)
            label = f"File payload ~{used} bytes / {capacity} bytes capacity"
        else:
            text = self.txt_secret.get("1.0", "end-1c")
            used = estimate_embedded_bytes(len(pack_inner_text(text)))
            label = f"Message ~{used} bytes / {capacity} bytes capacity"
        color = "#e74c3c" if used > capacity else "gray"
        self.lbl_capacity.configure(text=label, text_color=color)

    def _on_password_change(self, _event=None) -> None:
        """On password change.
        
        Args:
            _event:
        
        """
        text, color = _password_strength(self.ent_encode_pass.get())
        self.lbl_strength.configure(text=text, text_color=color)

    def _toggle_encode_password(self) -> None:
        """Toggle encode password.
        
        """
        show = "" if self.show_encode_pass.get() else "*"
        self.ent_encode_pass.configure(show=show)
        self.ent_encode_pass2.configure(show=show)

    def _toggle_decode_password(self) -> None:
        """Toggle decode password.
        
        """
        self.ent_decode_pass.configure(show="" if self.show_decode_pass.get() else "*")

    def select_encode_image(self) -> None:
        """Select encode image.
        
        """
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="Select Cover Image",
            initialdir=self._last_dir,
            filetypes=self._image_filetypes(),
        )
        if not path:
            return
        self.encode_img_path = path
        self._last_dir = str(Path(path).parent)
        self.lbl_encode_img.configure(text=os.path.basename(path))
        self._set_preview("encode", path)
        self._refresh_capacity()

    def select_decode_image(self) -> None:
        """Select decode image.
        
        """
        from tkinter import filedialog

        path = filedialog.askopenfilename(
            title="Select Stego Image",
            initialdir=self._last_dir,
            filetypes=[("PNG Image", "*.png"), ("All files", "*.*")],
        )
        if not path:
            return
        self.decode_img_path = path
        self._last_dir = str(Path(path).parent)
        self.lbl_decode_img.configure(text=os.path.basename(path))
        self._set_preview("decode", path)

    def load_text_file(self) -> None:
        """Load and parse text file.
        
        """
        from tkinter import filedialog, messagebox

        path = filedialog.askopenfilename(
            title="Load Text File",
            initialdir=self._last_dir,
            filetypes=[("Text files", "*.txt *.md *.csv *.json *.log"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            content = Path(path).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            messagebox.showerror("Error", "That file is not valid UTF-8 text. Use “Hide a File…” for binary data.")
            return
        self.encode_file_path = None
        self.txt_secret.configure(state="normal")
        self.txt_secret.delete("1.0", "end")
        self.txt_secret.insert("1.0", content)
        self._last_dir = str(Path(path).parent)
        self._refresh_capacity()

    def choose_hide_file(self) -> None:
        """Choose hide file.
        
        """
        from tkinter import filedialog

        path = filedialog.askopenfilename(title="Select File to Hide", initialdir=self._last_dir)
        if not path:
            return
        self.encode_file_path = path
        self._last_dir = str(Path(path).parent)
        size = Path(path).stat().st_size
        self.txt_secret.configure(state="normal")
        self.txt_secret.delete("1.0", "end")
        self.txt_secret.insert("1.0", f"[Hiding file]\n{os.path.basename(path)}\n{size} bytes\n\nThe file contents will be encrypted and embedded. Clear this box to switch back to a text message.")
        self.txt_secret.configure(state="disabled")
        self._refresh_capacity()

    def reset_payload(self) -> None:
        """Reset payload.
        
        """
        self.encode_file_path = None
        self.txt_secret.configure(state="normal")
        self.txt_secret.delete("1.0", "end")
        self._refresh_capacity()

    def process_encode(self) -> None:
        """Worker function for encode.
        
        """
        from tkinter import filedialog, messagebox

        if self.txt_secret.cget("state") == "normal":
            self.encode_file_path = None if self.txt_secret.get("1.0", "end-1c").strip() else self.encode_file_path

        if not self.encode_img_path:
            messagebox.showwarning("Warning", "Please select a cover image first.")
            return

        password = self.ent_encode_pass.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter an encryption password.")
            return
        if password != self.ent_encode_pass2.get():
            messagebox.showwarning("Warning", "Passwords do not match.")
            return
        if len(password) < 8:
            if not messagebox.askyesno(
                "Weak password",
                "This password is shorter than 8 characters. Hide the data anyway?",
            ):
                return

        if self.encode_file_path:
            message = None
        else:
            if self.txt_secret.cget("state") == "disabled":
                self.txt_secret.configure(state="normal")
            message = self.txt_secret.get("1.0", "end-1c")
            if not message.strip():
                messagebox.showwarning("Warning", "Please enter a secret message, or choose a file to hide.")
                return

        cover_stem = Path(self.encode_img_path).stem
        output_path = filedialog.asksaveasfilename(
            title="Save Stego Image As",
            initialdir=self._last_dir,
            initialfile=f"{cover_stem}_stego.png",
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png")],
        )
        if not output_path:
            return
        if not output_path.lower().endswith(".png"):
            output_path += ".png"
        self._last_dir = str(Path(output_path).parent)

        self.btn_encode.configure(state="disabled", text="Encoding...")
        self.encode_progress.set(0)
        threading.Thread(
            target=self._run_encode,
            args=(message, self.encode_file_path, password, output_path),
            daemon=True,
        ).start()

    def _update_encode_progress(self, progress: float) -> None:
        """Update encode progress.
        
        Args:
            progress:
        
        """
        self.root.after(0, self.encode_progress.set, progress)

    def _run_encode(self, message: Optional[str], file_path: Optional[str], password: str, output_path: str) -> None:
        """Worker function for encode.
        
        Args:
            message:
            file_path:
            password:
            output_path:
        
        """
        from tkinter import messagebox

        try:
            if file_path:
                StegoProcessor.encode_file(
                    self.encode_img_path,
                    file_path,
                    password,
                    output_path,
                    progress_callback=self._update_encode_progress,
                )
            else:
                StegoProcessor.encode_text(
                    self.encode_img_path,
                    message or "",
                    password,
                    output_path,
                    progress_callback=self._update_encode_progress,
                )
            self.root.after(0, lambda: messagebox.showinfo("Success", f"Payload encoded and saved to:\n{output_path}"))
            self.root.after(0, self._reset_encode_secrets)
        except ValueError as ve:
            self.root.after(0, lambda e=ve: messagebox.showerror("Error", str(e)))
        except Exception as e:
            self.root.after(0, lambda e=e: messagebox.showerror("Error", f"An unexpected error occurred:\n{e}"))
        finally:
            self.root.after(0, lambda: self.btn_encode.configure(state="normal", text="Encode & Save Image"))

    def _reset_encode_secrets(self) -> None:
        """Reset encode secrets.
        
        """
        self.encode_file_path = None
        self.txt_secret.configure(state="normal")
        self.txt_secret.delete("1.0", "end")
        self.ent_encode_pass.delete(0, "end")
        self.ent_encode_pass2.delete(0, "end")
        self._on_password_change()
        self._refresh_capacity()

    def process_decode(self) -> None:
        """Worker function for decode.
        
        """
        from tkinter import messagebox

        if not self.decode_img_path:
            messagebox.showwarning("Warning", "Please select a stego image first.")
            return
        password = self.ent_decode_pass.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a decryption password.")
            return

        self.btn_decode.configure(state="disabled", text="Extracting...")
        self.decode_progress.set(0)
        self.clear_extracted(keep_buttons=True)
        threading.Thread(target=self._run_decode, args=(password,), daemon=True).start()

    def _update_decode_progress(self, progress: float) -> None:
        """Update decode progress.
        
        Args:
            progress:
        
        """
        self.root.after(0, self.decode_progress.set, progress)

    def _run_decode(self, password: str) -> None:
        """Worker function for decode.
        
        Args:
            password:
        
        """
        from tkinter import messagebox

        try:
            result = StegoProcessor.decode(
                self.decode_img_path,
                password,
                progress_callback=self._update_decode_progress,
            )
            self.root.after(0, lambda r=result: self._show_decode_result(r))
        except ValueError as ve:
            self.root.after(0, lambda e=ve: messagebox.showerror("Error", str(e)))
        except Exception as e:
            self.root.after(0, lambda e=e: messagebox.showerror("Error", f"An unexpected error occurred:\n{e}"))
        finally:
            self.root.after(0, lambda: self.btn_decode.configure(state="normal", text="Extract & Decrypt Message"))

    def _show_decode_result(self, result: dict) -> None:
        """Show decode result.
        
        Args:
            result:
        
        """
        from tkinter import messagebox

        self._decode_result = result
        self.ent_decode_pass.delete(0, "end")
        self.txt_extracted.configure(state="normal")
        self.txt_extracted.delete("1.0", "end")

        if result["kind"] in ("text", "legacy_text"):
            self.txt_extracted.insert("1.0", result["text"] or "")
            self.lbl_decode_status.configure(text="Extracted a text message.")
            messagebox.showinfo("Success", "Message successfully extracted and decrypted.")
        else:
            name = result.get("filename") or "hidden.bin"
            size = len(result.get("data") or b"")
            self.txt_extracted.insert(
                "1.0",
                f"Hidden file recovered.\n\nFilename: {name}\nSize: {size} bytes\n\nUse “Save to File” to write it to disk.",
            )
            self.lbl_decode_status.configure(text=f"Extracted file: {name} ({size} bytes)")
            messagebox.showinfo("Success", f"Hidden file “{name}” was extracted. Save it to disk when ready.")

        self.txt_extracted.configure(state="disabled")
        self.btn_copy.configure(state="normal")
        self.btn_save_extracted.configure(state="normal")
        self.btn_clear_extracted.configure(state="normal")

    def copy_extracted(self) -> None:
        """Copy extracted.
        
        """
        from tkinter import messagebox

        if not self._decode_result:
            return
        if self._decode_result["kind"] in ("text", "legacy_text"):
            text = self._decode_result.get("text") or ""
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", "Message copied to the clipboard.")
        else:
            messagebox.showinfo("File payload", "This result is a file. Use “Save to File” instead of copy.")

    def save_extracted(self) -> None:
        """Save extracted to file.
        
        """
        from tkinter import filedialog, messagebox

        if not self._decode_result:
            return
        suggested = "message.txt"
        data = b""
        if self._decode_result["kind"] in ("text", "legacy_text"):
            data = (self._decode_result.get("text") or "").encode("utf-8")
            suggested = "message.txt"
        else:
            data = self._decode_result.get("data") or b""
            suggested = self._decode_result.get("filename") or "hidden.bin"

        path = filedialog.asksaveasfilename(
            title="Save Extracted Data",
            initialdir=self._last_dir,
            initialfile=suggested,
        )
        if not path:
            return
        Path(path).write_bytes(data)
        self._last_dir = str(Path(path).parent)
        messagebox.showinfo("Saved", f"Wrote {len(data)} bytes to:\n{path}")

    def clear_extracted(self, keep_buttons: bool = False) -> None:
        """Clear extracted.
        
        Args:
            keep_buttons (bool):
        
        """
        self._decode_result = None
        self.txt_extracted.configure(state="normal")
        self.txt_extracted.delete("1.0", "end")
        self.txt_extracted.configure(state="disabled")
        self.lbl_decode_status.configure(text="")
        if not keep_buttons:
            self.btn_copy.configure(state="disabled")
            self.btn_save_extracted.configure(state="disabled")
            self.btn_clear_extracted.configure(state="disabled")

    def run(self) -> None:
        """Worker function for parallel processing.
        
        """
        self.root.mainloop()


# --- CLI ---


def _prompt_password(password: Optional[str], confirm: bool = False) -> str:
    """Prompt password.
    
    Args:
        password:
        confirm (bool):
    
    Returns:
        The computed result
    
    """
    if password:
        return password
    value = getpass.getpass("Password: ")
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if value != again:
            raise SystemExit("Passwords do not match.")
    if not value:
        raise SystemExit("Password is required.")
    return value


def _build_parser() -> argparse.ArgumentParser:
    """Create parser.
    
    Returns:
        The computed result
    
    """
    parser = argparse.ArgumentParser(
        description="StegoCrypt: encrypt data and hide it in a PNG image.",
    )
    sub = parser.add_subparsers(dest="command")

    enc = sub.add_parser("encode", help="Encrypt and hide a message or file")
    enc.add_argument("cover", help="Cover image path")
    enc.add_argument("-o", "--output", required=True, help="Output PNG path")
    enc.add_argument("-m", "--message", help="Secret message text")
    enc.add_argument("--file", dest="hide_file", help="File to hide instead of text")
    enc.add_argument("-p", "--password", help="Encryption password (omit to be prompted)")

    dec = sub.add_parser("decode", help="Extract and decrypt a payload")
    dec.add_argument("image", help="Stego PNG path")
    dec.add_argument("-p", "--password", help="Decryption password (omit to be prompted)")
    dec.add_argument("-o", "--output", help="Write extracted file/text to this path")
    return parser


def run_cli(args: argparse.Namespace) -> int:
    """Worker function for cli.
    
    Args:
        args:
    
    Returns:
        int: Result of type int
    
    """
    if args.command == "encode":
        password = _prompt_password(args.password, confirm=True)
        if args.hide_file and args.message:
            raise SystemExit("Use either --message or --file, not both.")
        if args.hide_file:
            StegoProcessor.encode_file(args.cover, args.hide_file, password, args.output)
            print(f"Encoded file into {args.output}")
        else:
            message = args.message
            if message is None:
                message = sys.stdin.read()
            if not message:
                raise SystemExit("No message provided.")
            StegoProcessor.encode_text(args.cover, message, password, args.output)
            print(f"Encoded message into {args.output}")
        return 0

    if args.command == "decode":
        password = _prompt_password(args.password)
        result = StegoProcessor.decode(args.image, password)
        if args.output:
            if result["kind"] in ("text", "legacy_text"):
                Path(args.output).write_text(result["text"] or "", encoding="utf-8")
            else:
                Path(args.output).write_bytes(result["data"] or b"")
            print(f"Wrote extracted payload to {args.output}")
        elif result["kind"] in ("text", "legacy_text"):
            sys.stdout.write(result["text"] or "")
            if result["text"] and not result["text"].endswith("\n"):
                sys.stdout.write("\n")
        else:
            name = result.get("filename") or "hidden.bin"
            print(f"Extracted file '{name}' ({len(result.get('data') or b'')} bytes). Re-run with -o to save it.")
        return 0

    return 1


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point — parse arguments and run the main computation.
    
    Args:
        argv:
    
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    if argv and argv[0] in ("encode", "decode", "-h", "--help"):
        args = parser.parse_args(argv)
        if not args.command:
            parser.print_help()
            raise SystemExit(0)
        raise SystemExit(run_cli(args))

    try:
        StegoApp().run()
    except Exception as exc:
        if "customtkinter" in str(exc).lower() or type(exc).__name__ == "TclError":
            parser.print_help()
            raise SystemExit(
                "GUI could not start. Install dependencies with: pip install -r requirements.txt"
            ) from exc
        raise


if __name__ == "__main__":
    main()
