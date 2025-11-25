# 🎥 Video Steganography
A secure Video Steganography system that hides text file inside video frames using LSB, AES-GCM encryption, compression, and FFmpeg-based lossless assembly. Includes CLI and GUI.

A secure single-file Python application that hides and extracts secret files inside videos using Least Significant Bit (LSB) steganography.
This tool uses PNG frames, mandatory zlib compression, optional AES-GCM encryption, and assembles a lossless FFV1 video using FFmpeg, ensuring perfect data recovery.

It includes both a Tkinter GUI and a Command-Line Interface (CLI) — all inside one file: video_stegano.py
This tool allows embedding of any text file securely inside a video without noticeable visual changes.

📘 Project Overview

This system embeds secret data into a video by modifying the LSBs of pixel values across frames.
The workflow is:

1. Split input video → PNG frames
2. Embed compressed/encrypted payload bit-by-bit in pixel LSBs
3. Reassemble frames into a lossless MKV (FFV1 codec)
4. Extract data by reversing the process

To maintain quality and security:

1. Payload is always compressed using zlib
2. Optional AES-GCM encryption (password-based)
3. Scrypt key derivation ensures strong security
4. FFV1 output codec ensures zero information loss

You can embed any type of text file.

🚀 Features

🔒 Security
AES-GCM authenticated encryption (optional)
Strong Scrypt key-derivation
MD5 checksum for data integrity

🎞 Steganography Engine
LSB embedding using 1 or 2 bits per channel
PNG-first pipeline (lossless)
FFV1 output video guarantees perfect extraction
Automatic capacity calculation
Error handling for capacity, wrong password, corrupted header, etc.

📦 Payload Handling
Mandatory zlib compression
Supports any text file

🖥 GUI (Tkinter)
Clean, modern interface
Tabs: Embed & Extract
Filepickers, password support
Bits-per-channel selector (1 or 2)
Success & error dialogs

💻 Command Line Interface (CLI)
embed and extract commands
Optional encryption using --password
Interactive menu if no arguments are provided

📁 Single-File Architecture
Everything is contained inside: video_stegano.py

🧰 Tech Stack

This project uses a combination of Python libraries, cryptographic tools, GUI frameworks, and video-processing technologies to enable secure, lossless video steganography.

🔹 Programming Language: Python 3.x

🔹 Command Line Interface: argparse – CLI argument parsing (embed/extract)

🔹 Compression: zlib – mandatory payload compression before embedding

🔹 Video & Image Processing

OpenCV (cv2) – reading/writing frames, pixel-level LSB operations
FFmpeg – assembling PNG frames into FFV1 MKV & extracting frames

🔹 Security & Encryption

AES-GCM (authenticated encryption)
Scrypt (secure password-based key derivation)
cryptography Python library

🔹 GUI Framework

Tkinter – GUI layout and window management
ttk – modern widgets (tabs, buttons, radiobuttons, entries)

🧱 Architecture
video_stegano.py
│
├── Crypto Helpers
│     ├── Scrypt-based key derivation
│     ├── AES-GCM encryption / decryption
│
├── VideoSteganography Class
│     ├── LSB embed / extract
│     ├── Mandatory zlib compression
│     ├── Optional AES-GCM encryption
│     ├── 1024-byte JSON header
│     ├── Capacity calculation
│
├── FFmpeg Assembler
│     ├── Build PNG frames → FFV1 MKV
│
├── StegoGUI (Tkinter)
│     ├── Embed Tab
│     ├── Extract Tab
│     ├── Bits-per-channel option
│
└── CLI Interface
      ├── embed command
      ├── extract command
      ├── interactive menu

📦 Requirements
Python Dependencies
Install required packages: pip install opencv-python cryptography

System Requirement: FFmpeg
Required for PNG → MKV assembly.
Verify: ffmpeg -version

Install:
Windows: choco install ffmpeg
Linux: sudo apt install ffmpeg
Mac: brew install ffmpeg

▶️ How to Run

1️⃣ Run GUI: 
python video_stegano.py --gui

OR simply:
python video_stegano.py

…and choose GUI Mode from the prompt.

2️⃣ Run CLI:
🔐 Embed a file: python video_stegano.py embed --in-video shoot.mp4 --payload secret.txt --out-video stego.mkv --password mypassword

🔓 Extract the hidden file:   python video_stegano.py extract --in-video stego.mkv --out-file recovered_secret.bin --password mypassword

Password is optional, but required if encryption was used.

🧪 CLI Usage Summary
Help: python video_stegano.py --help

Commands:
Command	         Description
--gui	           Launch Tkinter GUI
embed	           Embed a secret file inside a video
extract	         Extract a hidden file from a stego video

🧠 Internal Workflow (Detailed)

1️⃣ Prepare Payload:
Read file bytes
Always compress using zlib
If password provided → encrypt with AES-GCM
Compute MD5 checksum
Build 1024-byte metadata header (JSON + padding)

2️⃣ Embed into Frames:
Convert header + payload to a bitstream
Embed LSBs into pixel RGB channels across PNG frames
Save frames: frame_000001.png, etc.

3️⃣ Reassemble Frames into Video: ffmpeg -framerate <fps> -i frame_%06d.png -c:v ffv1 -pix_fmt bgr24 output.mkv

4️⃣ Extraction (reverse):
Dump video to PNG frames
Extract bits
Parse header
Decrypt (if needed)
Decompress
Save recovered file

⚠️ Common Issues & Fixes
Issue	                      Cause	                               Solution
Payload too large 	        Video resolution too small	         Use 2 bits/channel OR larger video
FFmpeg fails to output      frames	FFmpeg not installed	       Install FFmpeg / add to PATH
Header not found	          Not a stego video or corrupted	     Use valid stego video
Corrupted output file	      Lossy codec used	                   Always use FFV1 (lossless)

⭐ Acknowledgements

This project uses:
OpenCV – frame extraction
FFmpeg – lossless video assembly
Cryptography – AES-GCM + Scrypt
Tkinter – GUI
