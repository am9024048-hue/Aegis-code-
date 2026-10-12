<div align="center">
  <h1>🛡️ Aegis Code</h1>
  <p><b>A Lightweight, Modular, Local-First Python SAST & Security Scanner</b></p>
  
  <p>
    <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python Version">
    <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/badge/SAST-Python-red.svg" alt="SAST">
  </p>
</div>

---

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🚀 Core Features</h3>
      <ul>
        <li><b>100% Local Privacy:</b> Runs entirely on your machine; no code leaves your device.</li>
        <li><b>Clean Architecture:</b> Decoupled engine and rules for high modularity.</li>
        <li><b>Rich Terminal UI:</b> Beautiful, color-coded table reports using <code>rich</code>.</li>
        <li><b>AST Parsing:</b> Native Python AST inspection for dynamic safety.</li>
      </ul>
    </td>
    <td width="50%" valign="top">
      <h3>🔍 Security Checks</h3>
      <ul>
        <li><b>Hardcoded Secrets:</b> Detects API keys, tokens, and exposed credentials via Regex.</li>
        <li><b>Dangerous Functions:</b> Flags dynamic execution calls like <code>eval()</code> and <code>exec()</code>.</li>
        <li><b>Insecure Imports:</b> Warns against unsafe standard modules like <code>pickle</code> or <code>telnetlib</code>.</li>
      </ul>
    </td>
  </tr>
</table>

---

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>💻 Installation</h3>
      <p>Install the required terminal UI library:</p>
      <pre><code>pip install rich</code></pre>
    </td>
    <td width="50%" valign="top">
      <h3>🛠️ Usage</h3>
      <p>Run the scanner on any Python file:</p>
      <pre><code>python aegis.py path/to/your_file.py</code></pre>
    </td>
  </tr>
</table>

---

### 🤝 Contributing & Support

* **Contributions:** Rule additions and improvements are welcome! Feel free to submit a PR or open an issue.
* **Support:** If you find this project useful, consider giving it a ⭐ Star on GitHub!
