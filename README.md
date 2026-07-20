StegoCrypt: AES-128 Image Steganography

A fully offline, standalone Python desktop application that securely hides encrypted text messages inside of standard image files.

This project combines AES-128 symmetric encryption (via the Fernet module) with Least Significant Bit (LSB) steganography. It is built with a thread-safe customtkinter GUI to ensure the application remains responsive during heavy image-processing workloads.

Core Features

Military-Grade Encryption: Uses PBKDF2HMAC with a SHA256 hash and 480,000 iterations to securely derive an encryption key from your password, appending a randomized 16-byte salt to every payload.

Invisible Data Masking: Modifies only the least significant bits of the Red, Green, and Blue pixel channels, rendering the hidden payload entirely invisible to the human eye.

Data Protection: Automatically calculates image capacity before encoding and enforces lossless .png outputs to prevent JPEG compression from destroying the steganographic bits.

Thread-Safe Processing: Heavy bitwise operations run on background daemon threads, keeping the progress bar and UI completely responsive without freezing the OS window.

Installation & Setup

Clone the repository to your local machine:

git clone https://github.com/YOUR-USERNAME/steganography-app.git
cd steganography-app


Install the required Python packages:

pip install -r requirements.txt


Run the application:

python main.py


How to Use

Encoding (Hiding a Message)

Navigate to the Encode & Hide tab.

Select a cover image (.png, .jpg, .jpeg, .bmp).

Type your secret message into the text box and provide a strong encryption password.

Click Encode & Save Image. The app will generate a new .png file containing your encrypted message.

Decoding (Extracting a Message)

Navigate to the Extract & Decrypt tab.

Select your previously encoded .png stego-image.

Enter the exact password used during encryption.

Click Extract & Decrypt Message. If the password is correct and the image data is intact, your original message will appear.
