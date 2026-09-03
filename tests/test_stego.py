import sys
import tempfile
import unittest
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from StegoCrypt import (  # noqa: E402
    CryptoProcessor,
    LEGACY_DELIMITER,
    StegoProcessor,
    image_capacity_bytes,
    pack_inner_file,
    pack_inner_text,
    unpack_inner,
)


def _make_image(path: Path, size: tuple[int, int] = (64, 64)) -> None:
    Image.new("RGB", size, color=(12, 84, 160)).save(path, format="PNG")


def _embed_legacy(cover: Path, message: str, password: str, output: Path) -> None:
    payload = CryptoProcessor.encrypt(message.encode("utf-8"), password) + LEGACY_DELIMITER
    img = Image.open(cover).convert("RGB")
    raw = bytearray(img.tobytes())
    bit_index = 0
    for byte in payload:
        for shift in range(7, -1, -1):
            raw[bit_index] = (raw[bit_index] & 0xFE) | ((byte >> shift) & 1)
            bit_index += 1
    Image.frombytes("RGB", img.size, bytes(raw)).save(output, format="PNG")


class CryptoTests(unittest.TestCase):
    def test_roundtrip(self) -> None:
        secret = "the eagle flies at midnight".encode("utf-8")
        payload = CryptoProcessor.encrypt(secret, "correct horse")
        self.assertEqual(CryptoProcessor.decrypt(payload, "correct horse"), secret)

    def test_wrong_password(self) -> None:
        payload = CryptoProcessor.encrypt(b"hidden", "alpha")
        with self.assertRaises(ValueError):
            CryptoProcessor.decrypt(payload, "beta")


class PackingTests(unittest.TestCase):
    def test_text_inner(self) -> None:
        kind, name, data = unpack_inner(pack_inner_text("hello"))
        self.assertEqual(kind, "text")
        self.assertIsNone(name)
        self.assertEqual(data.decode("utf-8"), "hello")

    def test_file_inner(self) -> None:
        kind, name, data = unpack_inner(pack_inner_file("notes.txt", b"abc"))
        self.assertEqual(kind, "file")
        self.assertEqual(name, "notes.txt")
        self.assertEqual(data, b"abc")


class StegoTests(unittest.TestCase):
    def test_text_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "stego.png"
            _make_image(cover)
            StegoProcessor.encode_text(str(cover), "secret payload", "pw-12345", str(stego))
            result = StegoProcessor.decode(str(stego), "pw-12345")
            self.assertEqual(result["kind"], "text")
            self.assertEqual(result["text"], "secret payload")

    def test_file_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "stego.png"
            hidden = Path(tmp) / "secret.bin"
            _make_image(cover, size=(128, 128))
            hidden.write_bytes(b"\x00\x01\x02binary")
            StegoProcessor.encode_file(str(cover), str(hidden), "file-pass", str(stego))
            result = StegoProcessor.decode(str(stego), "file-pass")
            self.assertEqual(result["kind"], "file")
            self.assertEqual(result["filename"], "secret.bin")
            self.assertEqual(result["data"], b"\x00\x01\x02binary")

    def test_wrong_password_on_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "stego.png"
            _make_image(cover)
            StegoProcessor.encode_text(str(cover), "nope", "right-password", str(stego))
            with self.assertRaises(ValueError):
                StegoProcessor.decode(str(stego), "wrong-password")

    def test_capacity_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "tiny.png"
            stego = Path(tmp) / "stego.png"
            _make_image(cover, size=(8, 8))
            huge = "x" * 5000
            with self.assertRaises(ValueError):
                StegoProcessor.encode_text(str(cover), huge, "password1", str(stego))

    def test_legacy_images_still_decode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cover = Path(tmp) / "cover.png"
            stego = Path(tmp) / "legacy.png"
            _make_image(cover, size=(96, 96))
            _embed_legacy(cover, "old format message", "legacy-pass", stego)
            result = StegoProcessor.decode(str(stego), "legacy-pass")
            self.assertEqual(result["kind"], "legacy_text")
            self.assertEqual(result["text"], "old format message")

    def test_capacity_helper(self) -> None:
        self.assertEqual(image_capacity_bytes(10, 10), 37)


if __name__ == "__main__":
    unittest.main()
