#!/usr/bin/env python3
"""
video_stegano.py — Single-file Video Steganography (GUI + CLI)
--------------------------------------------------------------
Features:
- Embed any file into a video (PNG-first LSB method) and reassemble with ffmpeg (FFV1).
- Extract hidden file back from the stego video.
- Optional AES-GCM encryption (password).
- Optional compression.
- Single file includes CLI and a clean/classy Tkinter GUI.

Save as: video_stegano.py
Dependencies:
  pip install opencv-python cryptography

Ensure ffmpeg is installed and on PATH:
  ffmpeg -version

Usage (GUI):
  python video_stegano.py --gui

Usage (CLI):
  python video_stegano.py embed --in-video input.mkv --payload secret.bin --out-video stego.mkv --password pass
  python video_stegano.py extract --in-video stego.mkv --out-file recovered.bin --password pass
"""

import os
import sys
import cv2
import zlib
import json
import hashlib
import tempfile
import shutil
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ----------------------------- Crypto Helpers -----------------------------
def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key with Scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))

def encrypt_data(plain: bytes, password: str):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    cipher = aes.encrypt(nonce, plain, None)
    return cipher, salt, nonce

def decrypt_data(cipher: bytes, password: str, salt: bytes, nonce: bytes):
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    return aes.decrypt(nonce, cipher, None)

# ----------------------------- FFmpeg Assembler -----------------------------
def assemble_video_from_pngs(png_dir: str, fps: float, out_path: str):
    """Use ffmpeg to assemble a sequence of PNGs into a lossless FFV1 MKV (or other container)."""
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    pattern = os.path.join(png_dir, "frame_%06d.png")
    cmd = [
        "ffmpeg", "-y", "-hide_banner", "-loglevel", "error",
        "-framerate", str(fps), "-i", pattern,
        "-c:v", "ffv1", "-pix_fmt", "bgr24", out_path
    ]
    subprocess.run(cmd, check=True)

# ----------------------------- Core Steganography -----------------------------
class VideoSteganography:
    HEADER_SIZE = 1024  # bytes reserved for header area

    def __init__(self, bits_per_channel: int = 1):
        assert bits_per_channel in (1, 2), "bits_per_channel must be 1 or 2"
        self.bits = bits_per_channel

    # embed / extract bit helpers
    def _embed_bits_into_byte(self, byte_val: int, bits: list) -> int:
        mask = (~((1 << self.bits) - 1)) & 0xFF
        pv = byte_val & mask
        for i, b in enumerate(bits):
            if b:
                pv |= (1 << (self.bits - 1 - i))
        return pv

    def _extract_bits_from_byte(self, byte_val: int) -> list:
        return [ (byte_val >> i) & 1 for i in range(self.bits - 1, -1, -1) ]

    def _bytes_to_bit_iter(self, data: bytes):
        for b in data:
            for i in range(7, -1, -1):
                yield (b >> i) & 1

    def _bits_to_bytes(self, bits: list) -> bytes:
        out = bytearray()
        cur = 0
        cnt = 0
        for bit in bits:
            cur = (cur << 1) | (bit & 1)
            cnt += 1
            if cnt == 8:
                out.append(cur)
                cur = 0
                cnt = 0
        if cnt:
            out.append(cur << (8 - cnt))
        return bytes(out)

    # header helpers
    def _make_header(self, payload_len: int, compressed: bool, md5: str, encrypted: bool, salt, nonce) -> bytes:
        obj = {
            "magic": "VSTEGO1",
            "len": int(payload_len),
            "compressed": int(bool(compressed)),
            "md5": md5,
            "encrypted": int(bool(encrypted)),
        }
        if salt is not None: obj["salt"] = salt.hex()
        if nonce is not None: obj["nonce"] = nonce.hex()
        j = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        if len(j) > self.HEADER_SIZE - 8:
            raise ValueError("Header JSON too large")
        prefix = len(j).to_bytes(8, "big")
        padding = b"\x00" * (self.HEADER_SIZE - 8 - len(j))
        return prefix + j + padding

    def _read_header_from_frame_array(self, arr) -> bytes:
        """Read HEADER_SIZE bytes worth of embedded header bits from a numpy image array."""
        bits_needed = self.HEADER_SIZE * 8
        bits = []
        h, w, ch = arr.shape
        for r in range(h):
            for c in range(w):
                for channel in range(min(3, ch)):
                    bits.extend(self._extract_bits_from_byte(int(arr[r, c, channel])))
                    if len(bits) >= bits_needed:
                        return self._bits_to_bytes(bits)[:self.HEADER_SIZE]
        return self._bits_to_bytes(bits)[:self.HEADER_SIZE]

    # embed
    def embed_file_into_video(self, in_video: str, payload_path: str, out_video: str,
                              password: str = None, compress: bool = True):
        if not os.path.exists(in_video):
            raise FileNotFoundError(f"Input video not found: {in_video}")
        if not os.path.exists(payload_path):
            raise FileNotFoundError(f"Payload file not found: {payload_path}")

        with open(payload_path, "rb") as f:
            payload = f.read()

        if compress:
            payload = zlib.compress(payload)
        md5 = hashlib.md5(payload).hexdigest()

        salt = None
        nonce = None
        encrypted_flag = False
        if password:
            payload, salt, nonce = encrypt_data(payload, password)
            encrypted_flag = True

        header = self._make_header(len(payload), compress, md5, encrypted_flag, salt, nonce)
        combined = header + payload

        cap = cv2.VideoCapture(in_video)
        if not cap.isOpened():
            raise RuntimeError("Failed to open input video (cv2.VideoCapture).")

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) or 0
        fps = float(cap.get(cv2.CAP_PROP_FPS) or 25.0)
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))

        # capacity check (rough)
        capacity_bytes = (height * width * 3 * max(1, total_frames) * self.bits) // 8
        reserved = self.HEADER_SIZE + 64
        usable = max(0, capacity_bytes - reserved)
        if len(combined) > usable:
            cap.release()
            raise ValueError(f"Payload too large for video capacity ({len(combined)} > {usable}).")

        tmpdir = tempfile.mkdtemp(prefix="vstego_frames_")
        try:
            bit_iter = self._bytes_to_bit_iter(combined)
            wrote_frames = 0
            done_embedding = False

            for frame_idx in range(1, (total_frames or 1) + 1):
                ret, frame = cap.read()
                if not ret:
                    break
                arr = frame.astype('uint8')
                stop_outer = False
                h_lim, w_lim = arr.shape[0], arr.shape[1]
                for r in range(h_lim):
                    for c in range(w_lim):
                        for ch in range(3):
                            bits = []
                            try:
                                for _ in range(self.bits):
                                    bits.append(next(bit_iter))
                            except StopIteration:
                                # partial bits for this byte
                                if bits:
                                    arr[r, c, ch] = self._embed_bits_into_byte(int(arr[r, c, ch]), bits)
                                done_embedding = True
                                stop_outer = True
                                break
                            arr[r, c, ch] = self._embed_bits_into_byte(int(arr[r, c, ch]), bits)
                        if stop_outer:
                            break
                    if stop_outer:
                        break

                cv2.imwrite(os.path.join(tmpdir, f"frame_{frame_idx:06d}.png"), arr)
                wrote_frames += 1

                if done_embedding:
                    # write remaining frames unmodified so lengths match
                    while True:
                        ret2, frame2 = cap.read()
                        if not ret2:
                            break
                        wrote_frames += 1
                        cv2.imwrite(os.path.join(tmpdir, f"frame_{wrote_frames:06d}.png"), frame2)
                    break

            cap.release()

            # assemble with ffmpeg
            assemble_video_from_pngs(tmpdir, fps, out_video)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # extract
    def extract_to_file(self, in_video: str, out_path: str, password: str = None):
        if not os.path.exists(in_video):
            raise FileNotFoundError(f"Input video not found: {in_video}")

        tmpdir = tempfile.mkdtemp(prefix="vstego_extract_")
        try:
            # dump frames to PNGs
            cmd = ["ffmpeg", "-y", "-hide_banner", "-loglevel", "error", "-i", in_video, os.path.join(tmpdir, "frame_%06d.png")]
            subprocess.run(cmd, check=True)

            # read first frames to get header
            header_raw = None
            header = None
            frame_files = sorted([f for f in os.listdir(tmpdir) if f.endswith(".png")])
            if not frame_files:
                raise RuntimeError("ffmpeg did not produce any frames from the input video.")

            # try to read header from first few frames
            for i, fname in enumerate(frame_files[:8], start=1):
                path = os.path.join(tmpdir, fname)
                arr = cv2.imread(path, cv2.IMREAD_UNCHANGED)
                if arr is None:
                    continue
                header_raw = self._read_header_from_frame_array(arr)
                # parse
                try:
                    ln = int.from_bytes(header_raw[:8], "big")
                    header_json = header_raw[8:8 + ln]
                    header = json.loads(header_json.decode("utf-8"))
                    if header.get("magic") == "VSTEGO1":
                        break
                    else:
                        header = None
                except Exception:
                    header = None

            if not header:
                raise RuntimeError("Header not found in first frames — this video may not contain a VSTEGO1 payload.")

            payload_len = int(header["len"])
            encrypted_flag = bool(int(header.get("encrypted", 0)))
            compressed_flag = bool(int(header.get("compressed", 0)))
            salt = bytes.fromhex(header["salt"]) if "salt" in header and header["salt"] else None
            nonce = bytes.fromhex(header["nonce"]) if "nonce" in header and header["nonce"] else None

            bits_needed = (self.HEADER_SIZE + payload_len) * 8
            bits = []

            # iterate frames and collect bits until enough
            for fname in frame_files:
                path = os.path.join(tmpdir, fname)
                arr = cv2.imread(path, cv2.IMREAD_UNCHANGED)
                if arr is None:
                    continue
                h_lim, w_lim = arr.shape[0], arr.shape[1]
                for r in range(h_lim):
                    for c in range(w_lim):
                        for ch in range(3):
                            bits.extend(self._extract_bits_from_byte(int(arr[r, c, ch])))
                            if len(bits) >= bits_needed:
                                break
                        if len(bits) >= bits_needed:
                            break
                    if len(bits) >= bits_needed:
                        break
                if len(bits) >= bits_needed:
                    break

            data_bytes = self._bits_to_bytes(bits)
            payload_bytes = data_bytes[self.HEADER_SIZE:self.HEADER_SIZE + payload_len]

            if encrypted_flag:
                if not password:
                    raise ValueError("Payload is encrypted — password required.")
                payload_bytes = decrypt_data(payload_bytes, password, salt, nonce)

            if compressed_flag:
                payload_bytes = zlib.decompress(payload_bytes)

            with open(out_path, "wb") as f:
                f.write(payload_bytes)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

# ----------------------------- GUI Application -----------------------------
class StegoGUI:
    def __init__(self, master):
        self.master = master
        master.title("🎥 Video Steganography Tool")
        master.geometry("760x480")
        master.configure(bg="#f4f6fa")

        self.vs = VideoSteganography(bits_per_channel=1)

        # Tkinter variables
        self.input_video = tk.StringVar()
        self.payload_file = tk.StringVar()
        self.output_video = tk.StringVar()
        self.extract_out = tk.StringVar()
        self.password = tk.StringVar()

        # --- Title ---
        title = tk.Label(
            master, 
            text="🎥 Video Steganography", 
            font=("Segoe UI Semibold", 18),
            bg="#f4f6fa", 
            fg="#2c3e50"
        )
        title.pack(pady=(15, 5))

        desc = tk.Label(
            master, 
            text="Hide or extract secret files securely inside videos 🔐",
            font=("Segoe UI", 10), 
            bg="#f4f6fa", 
            fg="#555"
        )
        desc.pack(pady=(0, 10))

        # --- Notebook (Tabs) ---
        notebook = ttk.Notebook(master)
        notebook.pack(expand=True, fill="both", padx=14, pady=8)

        self.embed_tab = ttk.Frame(notebook)
        self.extract_tab = ttk.Frame(notebook)
        notebook.add(self.embed_tab, text="Embed Secret")
        notebook.add(self.extract_tab, text="Extract Secret")

        # ===== EMBED TAB =====
        self._add_field(self.embed_tab, "🎞️ Select Input Video:", self.input_video, self.browse_video)
        self._add_field(self.embed_tab, "📁 Choose Secret File:", self.payload_file, self.browse_payload)
        self._add_field(self.embed_tab, "💾 Save Output Video As:", self.output_video, self.save_output_video, button_text="Save As")
        self._add_field(self.embed_tab, "🔑 Password (optional):", self.password, show="*")

        # Bits per channel
        bits_label = tk.Label(self.embed_tab, text="Bits Per Channel (data hiding depth):", bg="#f4f6fa", fg="#2c3e50", font=("Segoe UI", 10))
        bits_label.grid(row=4, column=0, sticky="e", padx=8, pady=(8, 2))
        self.bits_var = tk.IntVar(value=1)
        b1 = ttk.Radiobutton(self.embed_tab, text="1 (Safe & Subtle)", variable=self.bits_var, value=1, command=self._update_bits)
        b2 = ttk.Radiobutton(self.embed_tab, text="2 (More Capacity)", variable=self.bits_var, value=2, command=self._update_bits)
        b1.grid(row=4, column=1, sticky="w")
        b2.grid(row=4, column=1, sticky="e", padx=(0, 100))

        # Start button
        embed_btn = ttk.Button(self.embed_tab, text="🚀 Start Embedding", command=self.start_embedding)
        embed_btn.grid(row=5, column=1, pady=18)

        # ===== EXTRACT TAB =====
        self._add_field(self.extract_tab, "🎬 Select Stego Video:", self.input_video, self.browse_video)
        self._add_field(self.extract_tab, "💾 Save Extracted File As:", self.extract_out, self.save_output_file, button_text="Save As")
        self._add_field(self.extract_tab, "🔑 Password (if used):", self.password, show="*")

        extract_btn = ttk.Button(self.extract_tab, text="📂 Start Extraction", command=self.start_extraction)
        extract_btn.grid(row=3, column=1, pady=18)

        # Footer
        footer = tk.Label(
            master,
            text="⚙️ Requires ffmpeg installed and accessible via PATH. Recommended format: .mkv",
            bg="#f4f6fa",
            fg="#666",
            font=("Segoe UI", 9)
        )
        footer.pack(side="bottom", pady=(4, 10))

    # ---------- Helper Field Builder ----------
    def _add_field(self, frame, label_text, var, command=None, show=None, button_text="Select"):
        lbl = tk.Label(frame, text=label_text, bg="#f4f6fa", fg="#2c3e50", font=("Segoe UI", 10))
        lbl.grid(row=frame.grid_size()[1], column=0, sticky="e", padx=10, pady=8)

        entry = ttk.Entry(frame, textvariable=var, width=52, show=show)
        entry.grid(row=frame.grid_size()[1]-1, column=1, padx=5, pady=8)

        if command:
            btn = ttk.Button(frame, text=button_text, command=command)
            btn.grid(row=frame.grid_size()[1]-1, column=2, padx=6)

    # ---------- File Selectors ----------
    def browse_video(self):
        path = filedialog.askopenfilename(title="Select Video File", filetypes=[("Video Files", "*.mp4 *.mkv *.avi"), ("All Files", "*.*")])
        if path:
            self.input_video.set(path)

    def browse_payload(self):
        path = filedialog.askopenfilename(title="Select Secret File")
        if path:
            self.payload_file.set(path)

    def save_output_video(self):
        path = filedialog.asksaveasfilename(title="Save Stego Video As", defaultextension=".mkv", filetypes=[("MKV Files", "*.mkv"), ("All Files", "*.*")])
        if path:
            self.output_video.set(path)

    def save_output_file(self):
        path = filedialog.asksaveasfilename(title="Save Extracted File As", defaultextension=".bin")
        if path:
            self.extract_out.set(path)

    def _update_bits(self):
        self.vs = VideoSteganography(bits_per_channel=int(self.bits_var.get()))

    # ---------- Actions ----------
    def start_embedding(self):
        in_vid = self.input_video.get().strip()
        secret = self.payload_file.get().strip()
        out_vid = self.output_video.get().strip()
        pwd = self.password.get().strip() or None

        if not in_vid or not secret or not out_vid:
            messagebox.showwarning("⚠️ Missing Information", "Please select input video, secret file, and output destination.")
            return
        try:
            self.vs.embed_file_into_video(in_vid, secret, out_vid, password=pwd, compress=True)
            messagebox.showinfo("✅ Success", f"Secret embedded successfully!\n\nSaved to:\n{out_vid}")
        except Exception as e:
            messagebox.showerror("❌ Error", f"An error occurred:\n{e}")

    def start_extraction(self):
        in_vid = self.input_video.get().strip()
        out_file = self.extract_out.get().strip()
        pwd = self.password.get().strip() or None

        if not in_vid or not out_file:
            messagebox.showwarning("⚠️ Missing Information", "Please select stego video and output file destination.")
            return
        try:
            self.vs.extract_to_file(in_vid, out_file, password=pwd)
            messagebox.showinfo("✅ Success", f"File extracted successfully!\n\nSaved to:\n{out_file}")
        except Exception as e:
            messagebox.showerror("❌ Error", f"An error occurred:\n{e}")

# ----------------------------- CLI Handling -----------------------------
def run_cli():
    import argparse

    p = argparse.ArgumentParser(
        prog="video_stegano.py",
        description="Embed or extract files into/from videos"
    )
    p.add_argument("--gui", action="store_true", help="Run GUI directly")
    sub = p.add_subparsers(dest="cmd", help="Commands")

    # Embed command
    e = sub.add_parser("embed", help="Embed a file into a video")
    e.add_argument("--in-video", required=True, help="Path to input video")
    e.add_argument("--payload", required=True, help="Path to secret file to hide")
    e.add_argument("--out-video", required=True, help="Path to save the new stego video")
    e.add_argument("--password", default=None, help="Optional password for encryption")

    # Extract command
    x = sub.add_parser("extract", help="Extract a hidden file from a stego video")
    x.add_argument("--in-video", required=True, help="Path to stego video")
    x.add_argument("--out-file", required=True, help="Path to save the extracted file")
    x.add_argument("--password", default=None, help="Password (if encryption used)")

    args, _ = p.parse_known_args()

    # --- Mode Selection Prompt ---
    if len(sys.argv) == 1 and not args.gui:
        print("\n🎥 Video Steganography")
        print("----------------------")
        print("Choose mode:")
        print("1. GUI (Open visual interface)")
        print("2. CLI (Use command line)")
        choice = input("\nEnter your choice (1/2): ").strip()

        if choice == "1":
            print("\n🧩 GUI Mode Selected.")
            print("🎨 Launching GUI interface...\n")
            args.gui = True

        elif choice == "2":
            print("\n🧩 CLI Mode Selected.\n")
            print("You can run the application directly in your terminal with the help of following example commands :\n")
            print("▶ Embed a secret file inside a video:")
            print("   python video_stegano.py embed --in-video input.mp4 --payload secret.txt --out-video stego.mkv --password 1234\n")
            print("▶ Extract the hidden file back from the video:")
            print("   python video_stegano.py extract --in-video stego.mkv --out-file recovered.txt --password 1234\n")
            print("💡 Tip: Replace file names and passwords with your own values.\n")
            print("--------------------------------------------------------------")
            print("--------------------------------------------------------------\n")
            return

        else:
            print("❌ Invalid choice. Exiting.")
            return

    # --- Run GUI Mode ---
    if args.gui:
        root = tk.Tk()
        app = StegoGUI(root)
        root.mainloop()
        return

    # --- Run CLI Mode (embed / extract) ---
    vs = VideoSteganography(bits_per_channel=1)
    try:
        if args.cmd == "embed":
            vs.embed_file_into_video(
                args.in_video,
                args.payload,
                args.out_video,
                password=args.password,
                compress=True
            )
            print("✅ Embedding completed successfully.")
            print("Output saved as:", args.out_video)

        elif args.cmd == "extract":
            vs.extract_to_file(
                args.in_video,
                args.out_file,
                password=args.password
            )
            print("✅ Extraction completed successfully.")
            print("File saved as:", args.out_file)

        else:
            print("❌ Unknown command. Use --help to see available options.")

    except Exception as err:
        print("❌ Error:", err)
        sys.exit(1)


# ----------------------------- Entrypoint -----------------------------
if __name__ == "__main__":
    run_cli()

