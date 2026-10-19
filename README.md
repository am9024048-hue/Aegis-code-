# Aegis Code

A Lightweight, Modular, Local-First Python SAST & Security Scanner.

[![PyPI version](https://img.shields.io/pypi/v/aegis-python-security-scanner.svg)](https://pypi.org/project/aegis-python-security-scanner/)
[![Downloads](https://pepy.tech/badge/aegis-python-security-scanner)](https://pepy.tech/project/aegis-python-security-scanner)
[![GitHub stars](https://img.shields.io/github/stars/am9024048-hue/Aegis-code?style=social)](https://github.com/am9024048-hue/Aegis-code)
[![GitHub forks](https://img.shields.io/github/forks/am9024048-hue/Aegis-code?style=social)](https://github.com/am9024048-hue/Aegis-code)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

---

## 🚀 Overview

Aegis Code is an open-source, local-first Static Application Security Testing (SAST) tool designed for Python developers. It scans your source code for potential security vulnerabilities, hardcoded secrets, and unsafe programming practices without ever sending your code to external servers.

---

## ✨ Core Features

* 100% Local Privacy: Runs entirely on your local machine; no code or metrics ever leave your environment.
* Clean & Modular Architecture: Decoupled engine and security rules for high extensibility.
* Rich Terminal UI: Clear, color-coded tabular reporting powered by rich.
* AST Parsing: Native Python Abstract Syntax Tree (AST) inspection for robust and reliable static analysis.

---

## 🛡️ Security Checks

* Hardcoded Secrets: Detects API keys, private tokens, passwords, and exposed credentials using optimized regular expressions.
* Dangerous Functions: Flags execution of risky dynamic functions such as eval() and exec().
* Insecure Imports: Warns against imports of outdated or insecure standard library modules like pickle or telnetlib.

---

## 📦 Installation

Install the package official distribution directly from PyPI:

pip install aegis-python-security-scanner

---

## 💻 Usage

### Command Line Interface (CLI)
To run the scanner on any target Python file:

python -m aegis path/to/your_file.py

### Python Import
You can also import aegis inside your own Python projects:

import aegis

---

## 📄 License

This project is open-source and licensed under the terms of the MIT License.

---

## 🤝 Contributing & Support

* Contributions: Rule additions, bug fixes, and feature enhancements are welcome! Feel free to submit a Pull Request or open an Issue.
* Support: If you find this tool helpful, please consider giving it a Star on GitHub to help others discover it!
