# BruteForceX: Multi-Format Password Cracker

BruteForceX is a powerful password-cracking tool designed to test the strength of passwords protecting various file formats. Built with Python and featuring a responsive GUI powered by `tkinter`, this application supports brute-force attacks on PDFs, ZIP archives, Microsoft Office documents, and more. It allows users to customize character sets, password lengths, and file types for targeted cracking.

---

## Key Features

- **Multi-Format Support**: Crack passwords for PDFs, ZIP files, Word documents, Excel sheets, PowerPoint presentations, and more.
- **Customizable Brute-Force Settings**: Define character sets (letters, digits, punctuation) and password length ranges.
- **Real-Time Logs**: Monitor progress with detailed logs in the GUI.
- **Threaded Execution**: Ensures the application remains responsive during long-running operations.
- **Extensible Design**: Easily add support for additional file formats by extending the logic.

---

## Use Cases

- Recover lost passwords for encrypted files.
- Test the strength of passwords used in your documents.
- Learn about password security and the importance of strong passwords.

---

## Technologies Used

- Python
- Tkinter (GUI)
- PyPDF2 (PDF decryption)
- Pyzipper (ZIP decryption)
- msoffcrypto-tool (Microsoft Office decryption)
- Threading (For responsiveness)

---

## How to Use

1. Select the encrypted file you want to crack.
2. Choose the file type from the dropdown menu.
3. Configure the character set and password length range.
4. Click "Start" to begin the brute-force attack.
5. Monitor the logs for progress and results.
