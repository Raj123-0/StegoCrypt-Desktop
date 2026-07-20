"""
Secure Steganography Desktop App
Combines AES-128 Encryption (via Fernet) with LSB Image Steganography.

Prerequisites:
    pip install customtkinter pillow cryptography
"""

import os
import base64
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
from PIL import Image

# Cryptography imports
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- CRYPTOGRAPHY CLASS ---

class CryptoProcessor:
    """Handles AES encryption and decryption using PBKDF2HMAC for key derivation."""
    
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derives a secure 32-byte key from the given password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        # Fernet requires a base64url-encoded key
        return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

    @staticmethod
    def encrypt(text: str, password: str) -> bytes:
        """Encrypts a string and returns the payload containing salt + ciphertext."""
        salt = os.urandom(16)
        key = CryptoProcessor._derive_key(password, salt)
        f = Fernet(key)
        ciphertext = f.encrypt(text.encode('utf-8'))
        
        # We prepend the random salt to the ciphertext so the extractor can derive the same key
        return salt + ciphertext

    @staticmethod
    def decrypt(payload: bytes, password: str) -> str:
        """Decrypts a payload (salt + ciphertext) back to the original string."""
        if len(payload) < 16:
            raise ValueError("Corrupted data: payload is too short.")
            
        salt = payload[:16]
        ciphertext = payload[16:]
        key = CryptoProcessor._derive_key(password, salt)
        f = Fernet(key)
        
        try:
            plaintext = f.decrypt(ciphertext)
            return plaintext.decode('utf-8')
        except InvalidToken:
            raise ValueError("Incorrect password or corrupted image data.")


# --- STEGANOGRAPHY CLASS ---

class StegoProcessor:
    """Handles LSB encoding and decoding of binary data within images."""
    
    # A unique byte sequence used to identify the end of the hidden message
    DELIMITER = b'====END===='

    @staticmethod
    def encode(image_path: str, text: str, password: str, output_path: str, progress_callback=None):
        """Encrypts text and embeds it into the LSBs of an image's RGB channels."""
        # 1. Encrypt the data and append delimiter
        payload = CryptoProcessor.encrypt(text, password) + StegoProcessor.DELIMITER
        
        # 2. Convert payload bytes to a sequence of bits (0s and 1s)
        bits = []
        for byte in payload:
            for i in range(7, -1, -1):
                # Extract the i-th bit of the byte
                bits.append((byte >> i) & 1)
                
        # 3. Open image in RGB mode
        img = Image.open(image_path).convert('RGB')
        pixels = list(img.getdata())
        
        # 4. Check capacity (3 bits per pixel: R, G, B channels)
        max_capacity_bits = len(pixels) * 3
        payload_len = len(bits)
        
        if payload_len > max_capacity_bits:
            raise ValueError(f"Image is too small! Max capacity: {max_capacity_bits//8} bytes. Needed: {len(payload)} bytes.")
        
        # 5. Hide data inside pixels
        encoded_pixels = []
        bit_idx = 0
        
        # Update progress occasionally
        update_interval = max(1, payload_len // 100) # Update roughly 100 times

        for r, g, b in pixels:
            # Modify R channel
            if bit_idx < payload_len:
                r = (r & ~1) | bits[bit_idx]
                bit_idx += 1
                
            # Modify G channel
            if bit_idx < payload_len:
                g = (g & ~1) | bits[bit_idx]
                bit_idx += 1
                
            # Modify B channel
            if bit_idx < payload_len:
                b = (b & ~1) | bits[bit_idx]
                bit_idx += 1
                
            encoded_pixels.append((r, g, b))
            
            if progress_callback and (bit_idx % update_interval == 0 or bit_idx >= payload_len):
                # We calculate progress up to 90% during embedding, 
                # leaving 10% for saving the image
                progress = (bit_idx / payload_len) * 0.9
                progress_callback(progress)
            
            # Stop if all bits are embedded to save processing time
            if bit_idx >= payload_len:
                break
                
        if progress_callback:
            progress_callback(0.9)
            
        # Append any remaining unmodified pixels
        pixels_processed = len(encoded_pixels)
        if pixels_processed < len(pixels):
            encoded_pixels.extend(pixels[pixels_processed:])
            
        # 6. Save image as PNG (Lossless format to prevent destroying LSBs)
        img.putdata(encoded_pixels)
        img.save(output_path, format="PNG")
        
        if progress_callback:
            progress_callback(1.0)

    @staticmethod
    def decode(image_path: str, password: str) -> str:
        """Extracts bits from an image, finds the delimiter, and decrypts the payload."""
        img = Image.open(image_path).convert('RGB')
        pixels = img.getdata()
        
        extracted_bytes = bytearray()
        current_byte = 0
        bit_count = 0
        delimiter_len = len(StegoProcessor.DELIMITER)
        
        # 1. Extract LSBs from pixels
        for pixel in pixels:
            for color in pixel: # R, G, B
                # Shift current byte left by 1 and add the LSB of the color channel
                current_byte = (current_byte << 1) | (color & 1)
                bit_count += 1
                
                # When 8 bits form a byte, store it and check for the delimiter
                if bit_count == 8:
                    extracted_bytes.append(current_byte)
                    current_byte = 0
                    bit_count = 0
                    
                    # Check if the recent bytes match our delimiter
                    if len(extracted_bytes) >= delimiter_len:
                        if extracted_bytes[-delimiter_len:] == StegoProcessor.DELIMITER:
                            # 2. Delimiter found, separate payload from delimiter
                            payload_bytes = bytes(extracted_bytes[:-delimiter_len])
                            
                            # 3. Decrypt payload
                            return CryptoProcessor.decrypt(payload_bytes, password)
                            
        raise ValueError("No hidden data found, or the image has been altered/compressed.")


# --- GUI CLASS ---

class StegoApp(ctk.CTk):
    """Main Application GUI using customtkinter."""
    def __init__(self):
        super().__init__()
        
        # Configure window
        self.title("AES-128 Steganography Tool")
        self.geometry("750x600")
        self.resizable(False, False)
        
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Main Tabview
        self.tabview = ctk.CTkTabview(self, width=700, height=550)
        self.tabview.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        
        self.tabview.add("Encode & Hide")
        self.tabview.add("Extract & Decrypt")
        
        self.setup_encode_tab()
        self.setup_decode_tab()
        
    def setup_encode_tab(self):
        tab = self.tabview.tab("Encode & Hide")
        tab.grid_columnconfigure(1, weight=1)
        
        # Image selection
        self.encode_img_path = None
        self.btn_select_encode_img = ctk.CTkButton(tab, text="Select Cover Image", command=self.select_encode_image)
        self.btn_select_encode_img.grid(row=0, column=0, padx=20, pady=15, sticky="w")
        
        self.lbl_encode_img = ctk.CTkLabel(tab, text="No image selected", text_color="gray")
        self.lbl_encode_img.grid(row=0, column=1, padx=20, pady=15, sticky="w")
        
        # Secret text
        self.lbl_secret_text = ctk.CTkLabel(tab, text="Secret Message:")
        self.lbl_secret_text.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.txt_secret = ctk.CTkTextbox(tab, height=180)
        self.txt_secret.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")
        
        # Password
        self.lbl_encode_pass = ctk.CTkLabel(tab, text="Encryption Password:")
        self.lbl_encode_pass.grid(row=3, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.ent_encode_pass = ctk.CTkEntry(tab, show="*", width=300, placeholder_text="Enter a secure password")
        self.ent_encode_pass.grid(row=4, column=0, columnspan=2, padx=20, pady=10, sticky="w")
        
        # Action button
        self.btn_encode = ctk.CTkButton(tab, text="Encode & Save Image", command=self.process_encode, fg_color="#27ae60", hover_color="#219653")
        self.btn_encode.grid(row=5, column=0, columnspan=2, padx=20, pady=(20, 10))
        
        # Progress Bar
        self.encode_progress = ctk.CTkProgressBar(tab, width=400)
        self.encode_progress.grid(row=6, column=0, columnspan=2, padx=20, pady=(0, 20))
        self.encode_progress.set(0)

    def setup_decode_tab(self):
        tab = self.tabview.tab("Extract & Decrypt")
        tab.grid_columnconfigure(1, weight=1)
        
        # Image selection
        self.decode_img_path = None
        self.btn_select_decode_img = ctk.CTkButton(tab, text="Select Stego Image", command=self.select_decode_image)
        self.btn_select_decode_img.grid(row=0, column=0, padx=20, pady=15, sticky="w")
        
        self.lbl_decode_img = ctk.CTkLabel(tab, text="No image selected", text_color="gray")
        self.lbl_decode_img.grid(row=0, column=1, padx=20, pady=15, sticky="w")
        
        # Password
        self.lbl_decode_pass = ctk.CTkLabel(tab, text="Decryption Password:")
        self.lbl_decode_pass.grid(row=1, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.ent_decode_pass = ctk.CTkEntry(tab, show="*", width=300, placeholder_text="Enter decryption password")
        self.ent_decode_pass.grid(row=2, column=0, columnspan=2, padx=20, pady=10, sticky="w")
        
        # Action button
        self.btn_decode = ctk.CTkButton(tab, text="Extract & Decrypt Message", command=self.process_decode)
        self.btn_decode.grid(row=3, column=0, columnspan=2, padx=20, pady=20)
        
        # Extracted text
        self.lbl_extracted_text = ctk.CTkLabel(tab, text="Extracted Message:")
        self.lbl_extracted_text.grid(row=4, column=0, padx=20, pady=(10, 0), sticky="w")
        
        self.txt_extracted = ctk.CTkTextbox(tab, height=180, state="disabled")
        self.txt_extracted.grid(row=5, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")

    def select_encode_image(self):
        path = filedialog.askopenfilename(title="Select Cover Image", filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if path:
            self.encode_img_path = path
            self.lbl_encode_img.configure(text=os.path.basename(path))
            
    def select_decode_image(self):
        path = filedialog.askopenfilename(title="Select Stego Image", filetypes=[("PNG Image", "*.png")])
        if path:
            self.decode_img_path = path
            self.lbl_decode_img.configure(text=os.path.basename(path))
            
    def process_encode(self):
        if not self.encode_img_path:
            messagebox.showwarning("Warning", "Please select a cover image first.")
            return
            
        message = self.txt_secret.get("1.0", "end-1c")
        if not message.strip():
            messagebox.showwarning("Warning", "Please enter a secret message to hide.")
            return
            
        password = self.ent_encode_pass.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter an encryption password.")
            return
            
        output_path = filedialog.asksaveasfilename(
            title="Save Stego Image As", 
            defaultextension=".png", 
            filetypes=[("PNG Image", "*.png")]
        )
        if not output_path:
            return
            
        # Strictly enforce .png extension to prevent LSB data loss from JPEG compression
        if not output_path.lower().endswith('.png'):
            output_path += '.png'
            
        # Run encoding in a separate thread to prevent freezing the GUI
        self.btn_encode.configure(state="disabled", text="Encoding...")
        threading.Thread(target=self._run_encode, args=(message, password, output_path), daemon=True).start()
        
    def _update_encode_progress(self, progress: float):
        self.after(0, self.encode_progress.set, progress)

    def _run_encode(self, message, password, output_path):
        self.after(0, self.encode_progress.set, 0)
        try:
            StegoProcessor.encode(
                self.encode_img_path, 
                message, 
                password, 
                output_path,
                progress_callback=self._update_encode_progress
            )
            self.after(0, lambda: messagebox.showinfo("Success", "Message successfully encoded and image saved!"))
            # Clear text upon success for security
            self.after(0, lambda: self.txt_secret.delete("1.0", "end"))
            self.after(0, lambda: self.ent_encode_pass.delete(0, "end"))
        except ValueError as ve:
            self.after(0, lambda e=ve: messagebox.showerror("Error", str(e)))
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Error", f"An unexpected error occurred:\n{str(e)}"))
        finally:
            self.after(0, lambda: self.btn_encode.configure(state="normal", text="Encode & Save Image"))

    def process_decode(self):
        if not self.decode_img_path:
            messagebox.showwarning("Warning", "Please select a stego image first.")
            return
            
        password = self.ent_decode_pass.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a decryption password.")
            return
            
        self.btn_decode.configure(state="disabled", text="Extracting...")
        self.txt_extracted.configure(state="normal")
        self.txt_extracted.delete("1.0", "end")
        self.txt_extracted.configure(state="disabled")
        
        # Run decoding in a separate thread to prevent freezing the GUI
        threading.Thread(target=self._run_decode, args=(password,), daemon=True).start()
        
    def _run_decode(self, password):
        try:
            message = StegoProcessor.decode(self.decode_img_path, password)
            self.after(0, lambda msg=message: self._update_extracted_text(msg))
            self.after(0, lambda: messagebox.showinfo("Success", "Message successfully extracted and decrypted!"))
            self.after(0, lambda: self.ent_decode_pass.delete(0, "end"))
        except ValueError as ve:
            self.after(0, lambda e=ve: messagebox.showerror("Error", str(e)))
        except Exception as e:
            self.after(0, lambda e=e: messagebox.showerror("Error", f"An unexpected error occurred:\n{str(e)}"))
        finally:
            self.after(0, lambda: self.btn_decode.configure(state="normal", text="Extract & Decrypt Message"))
            
    def _update_extracted_text(self, message):
        self.txt_extracted.configure(state="normal")
        self.txt_extracted.insert("1.0", message)
        self.txt_extracted.configure(state="disabled")

if __name__ == "__main__":
    app = StegoApp()
    app.mainloop()
