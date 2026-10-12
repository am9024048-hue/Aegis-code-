# 🛡️ Aegis Code

> **A Lightweight, Local Static Application Security Testing (SAST) Tool for Python**

A lightweight, local Static Application Security Testing (SAST) tool built with Python. It uses Python's `ast` module and regex patterns to perform local security checks on Python source files.

---

## 🚀 Features

- **100% Local:** Runs entirely on your machine; no code is sent to external servers.
- **AST Parsing:** Uses Python's native `ast` module to analyze code structure.
- **Security Checks:** 
  - Detects potential hardcoded secrets (API keys, passwords).
  - Flags dangerous function usage (`eval`, `exec`).
  - Warns against insecure module imports (`pickle`, `telnetlib`).

---

## 💻 Usage

Run the scanner directly from your terminal by passing the path of the Python file you want to check:

```bash
python aegis.py path/to/your_file.py
Contributing
Contributions and rule additions are welcome! Feel free to open an issue or submit a pull request.
⭐ Support
If you find this project useful, consider giving it a Star!
