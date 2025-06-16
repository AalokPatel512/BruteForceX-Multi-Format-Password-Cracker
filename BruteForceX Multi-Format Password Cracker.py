import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
import itertools
from string import ascii_letters, digits, punctuation
import threading

# Supported Libraries
try:
    import PyPDF2
    import pyzipper
    import msoffcrypto
except ImportError:
    messagebox.showerror("Missing Libraries", "Please install required modules:\npip install PyPDF2 pyzipper msoffcrypto-tool")

class MultiFormatPasswordCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Format Password Cracker")
        self.root.geometry("800x650")

        self.file_path = ""
        self.running = False

        self.create_widgets()

    def create_widgets(self):
        # --- File Selection ---
        tk.Label(self.root, text="Select Encrypted File:").pack(anchor='w', padx=10, pady=5)
        self.file_label = tk.Entry(self.root, width=60)
        self.file_label.pack(side='left', padx=10)
        tk.Button(self.root, text="Browse", command=self.browse_file).pack(side='left')

        # --- File Type Dropdown ---
        tk.Label(self.root, text="File Type:").pack(anchor='w', padx=10, pady=5)
        self.file_type = ttk.Combobox(self.root, values=[
            "pdf", "zip", "docx", "xlsx", "pptx", "rar", "7z", "enc", "crypt", "eml", "msg", "jpg", "png", "mp4", "mkv"
        ], state="readonly")
        self.file_type.current(0)
        self.file_type.pack(padx=10, pady=5)

        # --- Character Set Options ---
        tk.Label(self.root, text="Character Sets to Use:").pack(anchor='w', padx=10, pady=5)

        self.use_letters = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=False)
        self.use_punct = tk.BooleanVar(value=False)

        tk.Checkbutton(self.root, text="Letters (a-zA-Z)", variable=self.use_letters).pack(anchor='w', padx=20)
        tk.Checkbutton(self.root, text="Digits (0-9)", variable=self.use_digits).pack(anchor='w', padx=20)
        tk.Checkbutton(self.root, text="Punctuation", variable=self.use_punct).pack(anchor='w', padx=20)

        # --- Length Settings ---
        len_frame = tk.Frame(self.root)
        len_frame.pack(pady=10)

        tk.Label(len_frame, text="Start Length:").grid(row=0, column=0)
        self.start_len = tk.Entry(len_frame, width=5)
        self.start_len.grid(row=0, column=1)
        self.start_len.insert(0, "1")

        tk.Label(len_frame, text="Max Length:").grid(row=0, column=2, padx=(10, 0))
        self.max_len = tk.Entry(len_frame, width=5)
        self.max_len.grid(row=0, column=3)
        self.max_len.insert(0, "6")

        # --- Buttons ---
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)

        self.start_btn = tk.Button(btn_frame, text="Start", width=10, command=self.start_attack)
        self.start_btn.grid(row=0, column=0)

        self.stop_btn = tk.Button(btn_frame, text="Stop", width=10, state=tk.DISABLED, command=self.stop_attack)
        self.stop_btn.grid(row=0, column=1, padx=5)

        # --- Log Area ---
        tk.Label(self.root, text="Logs:").pack(anchor='w', padx=10)
        self.log_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=90, height=15)
        self.log_area.pack(padx=10, pady=5)

    def log(self, msg):
        self.log_area.insert(tk.END, msg + "\n")
        self.log_area.see(tk.END)

    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[
            ("All Files", "*.*"),
            ("PDF Files", "*.pdf"),
            ("ZIP Files", "*.zip"),
            ("Word Documents", "*.docx"),
            ("Excel Spreadsheets", "*.xlsx"),
            ("PowerPoint Presentations", "*.pptx"),
            ("RAR Archives", "*.rar"),
            ("7Z Archives", "*.7z"),
            ("Encrypted Files", "*.enc *.crypt"),
            ("Email Files", "*.eml *.msg"),
            ("Image Files", "*.jpg *.jpeg *.png *.gif"),
            ("Video Files", "*.mp4 *.mkv *.avi")
        ])
        if file_path:
            self.file_label.delete(0, tk.END)
            self.file_label.insert(0, file_path)
            self.file_path = file_path
            self.log(f"[+] Selected file: {file_path}")

    def get_char_set(self):
        char_set = ""
        if self.use_letters.get():
            char_set += ascii_letters
        if self.use_digits.get():
            char_set += digits
        if self.use_punct.get():
            char_set += punctuation
        if not char_set:
            self.log("[!] No character set selected. Defaulting to letters.")
            return ascii_letters
        return char_set

    def start_attack(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file first.")
            return

        try:
            start_length = int(self.start_len.get())
            max_length = int(self.max_len.get())
            if start_length < 1 or max_length < 1:
                raise ValueError
        except ValueError:
            messagebox.showerror("Input Error", "Please enter valid positive integers for lengths.")
            return

        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.log("[+] Starting password attack...")

        thread = threading.Thread(target=self.run_attack, args=(start_length, max_length))
        thread.start()

    def stop_attack(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("[!] Attack stopped by user.")

    def run_attack(self, start_length, max_length):
        char_set = self.get_char_set()
        file_type = self.file_type.get()
        self.log(f"[*] Using character set: {char_set}")
        self.log(f"[*] Target file type: {file_type}\n")

        for length in range(start_length, max_length + 1):
            if not self.running:
                break
            self.log(f"\n[+] Trying passwords of length {length}...")
            for combo in itertools.product(char_set, repeat=length):
                if not self.running:
                    return
                password = ''.join(combo)
                self.log(f"[-] Trying: {password}")

                try:
                    if file_type == "pdf":
                        with open(self.file_path, "rb") as f:
                            pdf = PyPDF2.PdfReader(f)
                            if pdf.is_encrypted:
                                result = pdf.decrypt(password)
                                if result == 1 or result == 2:
                                    self.log(f"[+] ✅ Password found: {password}")
                                    self.stop_attack()
                                    return

                    elif file_type == "zip":
                        with pyzipper.AESZipFile(self.file_path) as zf:
                            zf.extractall(pwd=password.encode())
                            self.log(f"[+] ✅ Password found: {password}")
                            self.stop_attack()
                            return

                    elif file_type in ["docx", "xlsx", "pptx"]:
                        with open(self.file_path, "rb") as f:
                            office_file = msoffcrypto.OfficeFile(f)
                            if office_file.is_encrypted():
                                decrypted = office_file.decrypt(password)
                                self.log(f"[+] ✅ Password found: {password}")
                                self.stop_attack()
                                return

                    elif file_type in ["rar", "7z", "enc", "crypt", "eml", "msg", "jpg", "png", "mp4", "mkv"]:
                        self.log(f"[⚠️] Format '{file_type}' is not yet supported for cracking. Add custom logic here.")

                except Exception as e:
                    continue  # Skip invalid ones silently

        self.log("\n[!] Max length reached or stopped before finding the password.")

if __name__ == "__main__":
    root = tk.Tk()
    app = MultiFormatPasswordCrackerGUI(root)
    root.mainloop()