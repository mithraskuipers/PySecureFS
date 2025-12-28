
# PySecureFS

## Overview

**PySecureFS** is a fully-featured, cross-platform, single-file Python GUI application for quickly sharing files over a local network. Its main goal is to allow users to share files securely and efficiently within a network, without relying on external dependencies, complex configurations, or multiple files. Unlike standard Python HTTP servers, this script provides:

- Optional **user authentication** with rate limiting and account lockouts  
- **HTTPS support** with the ability to generate self-signed certificates  
- **File upload support** via a user-friendly web interface  
- Real-time **GUI controls** using Tkinter  
- Automatic **session management** and cleanup  
- Integrated **logging** to console, file, and optional GUI log window  

### Screenshot

![PySecureFS Screenshot](pysecurefs.png)  

## Features

### Security
- Optional **basic authentication** with configurable username and password  
- **Rate limiting** and **lockout mechanism** to prevent brute-force attacks  
- **Password hashing** using PBKDF2 with configurable iterations and salt  
- Session management with expiration and automatic cleanup  

### HTTPS / TLS
- Supports **HTTPS connections** using user-provided certificates  
- Can generate **self-signed certificates** automatically using Python's cryptography library  
- TLS configuration with a default validity period of 365 days  

### File Management
- **File upload** with size limits  
- Files are automatically renamed to prevent conflicts  
- Provides a clean **web interface** for browsing and downloading files  
- Displays file sizes and upload status on the web page  

### Logging
- Logs all events to both console and a log file (`python-file-server.log`)  
- GUI log viewer for easy monitoring of activity  

### Miscellaneous
- **Single-file deployment:** Everything is contained in one Python file for portability  
- Supports **reusable TCP socket** for rapid server restarts  
- Automatic cleanup of sessions, certificates, and log files on exit  

---

## Dependencies

- Standard Python libraries:  
  `http.server`, `socketserver`, `threading`, `os`, `ssl`, `logging`, `tkinter`, `pathlib`, `socket`, `base64`, `hashlib`, `hmac`, `secrets`, `time`, `atexit`, `re`, `datetime`, `collections`, `webbrowser`  

- Optional for HTTPS certificate generation:  
  `cryptography`  

- Optional for clipboard integration:  
  `pyperclip`  

> No installation is required for the standard server functionality. Installing `cryptography` and `pyperclip` enhances HTTPS and clipboard features.  

---

## Usage

1. **Run the script:**  
```bash
python pysecurefs.py