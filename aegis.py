import ast
import re
import sys
from pathlib import Path
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

# ==============================================================================
# 1. CORE DOMAIN: Finding / Issue Model
# ==============================================================================
class Vulnerability:
    """Represents a single detected security issue."""
    def __init__(self, file_path: str, line: int, severity: str, category: str, description: str):
        self.file_path = file_path
        self.line = line
        self.severity = severity  # HIGH, MEDIUM, LOW
        self.category = category
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for future Server/API/JSON responses."""
        return {
            "file_path": self.file_path,
            "line": self.line,
            "severity": self.severity,
            "category": self.category,
            "description": self.description
        }

# ==============================================================================
# 2. RULES ENGINE (Extensible / Plugin-ready Architecture)
# ==============================================================================
class SecurityRule:
    """Base class for all security rules."""
    def analyze_ast(self, tree: ast.AST, file_path: str) -> List[Vulnerability]:
        return []

    def analyze_regex(self, content: str, file_path: str) -> List[Vulnerability]:
        return []

class HardcodedSecretsRule(SecurityRule):
    """Detects exposed API keys and sensitive tokens using Regex."""
    PATTERNS = [
        (r'(?i)(api[_-]?key|secret[_-]?key|token|auth[_-]?token)\s*=\s*[\'"][A-Za-z0-9_\-]{16,}[\'"]', "Potential hardcoded API secret / token detected"),
        (r'AIzaSy[A-Za-z0-9_\-]{33}', "Google API Key detected"),
        (r'sk-[A-Za-z0-9]{32,}', "OpenAI / API Secret Key detected")
    ]

    def analyze_regex(self, content: str, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            for pattern, desc in self.PATTERNS:
                if re.search(pattern, line):
                    vulnerabilities.append(Vulnerability(file_path, idx, "HIGH", "Hardcoded Secret", desc))
        return vulnerabilities

class InsecureFunctionsRule(SecurityRule):
    """Detects dangerous dynamic code execution like eval() and exec()."""
    def analyze_ast(self, tree: ast.AST, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in ['eval', 'exec']:
                    vulnerabilities.append(
                        Vulnerability(file_path, node.lineno, "HIGH", "Dynamic Execution", f"Use of dangerous function '{node.func.id}' detected")
                    )
        return vulnerabilities

class InsecureImportsRule(SecurityRule):
    """Warns against importing insecure or deprecated modules."""
    INSECURE_MODULES = {'pickle', 'telnetlib', 'xmlrpclib'}

    def analyze_ast(self, tree: ast.AST, file_path: str) -> List[Vulnerability]:
        vulnerabilities = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.INSECURE_MODULES:
                        vulnerabilities.append(
                            Vulnerability(file_path, node.lineno, "MEDIUM", "Insecure Import", f"Import of insecure module '{alias.name}' detected")
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module in self.INSECURE_MODULES:
                    vulnerabilities.append(
                        Vulnerability(file_path, node.lineno, "MEDIUM", "Insecure Import", f"Import from insecure module '{node.module}' detected")
                    )
        return vulnerabilities

# ==============================================================================
# 3. ANALYSIS ENGINE (Independent Core - Server / CLI / Cloud Compatible)
# ==============================================================================
class AegisEngine:
    """Core SAST scanner decoupled from UI or CLI logic."""
    def __init__(self):
        self.rules: List[SecurityRule] = [
            HardcodedSecretsRule(),
            InsecureFunctionsRule(),
            InsecureImportsRule()
        ]

    def scan_code(self, content: str, file_path: str = "snippet.py") -> List[Vulnerability]:
        """Scans code content in-memory (Ideal for Serverless / API)."""
        findings = []
        
        # AST Analysis
        try:
            tree = ast.parse(content, filename=file_path)
            for rule in self.rules:
                findings.extend(rule.analyze_ast(tree, file_path))
        except SyntaxError as e:
            findings.append(Vulnerability(file_path, e.lineno or 1, "HIGH", "Syntax Error", f"Unable to parse file: {e.msg}"))

        # Regex Analysis
        for rule in self.rules:
            findings.extend(rule.analyze_regex(content, file_path))

        return findings

    def scan_file(self, target_path: Path) -> List[Vulnerability]:
        """Scans a physical file."""
        if not target_path.exists():
            return [Vulnerability(str(target_path), 0, "HIGH", "File Error", "File does not exist")]
        
        try:
            content = target_path.read_text(encoding='utf-8')
            return self.scan_code(content, str(target_path))
        except Exception as e:
            return [Vulnerability(str(target_path), 0, "HIGH", "Read Error", f"Failed to read file: {str(e)}")]

# ==============================================================================
# 4. REPORTER INTERFACE (Rich Terminal UI)
# ==============================================================================
class RichReporter:
    """Handles aesthetic rendering for CLI terminal output using `rich`."""
    def __init__(self):
        self.console = Console()

    def print_banner(self):
        banner_text = Text("AEGIS CODE - SAST Security Scanner", style="bold cyan")
        self.console.print(Panel(banner_text, border_style="blue", expand=False))

    def render_report(self, findings: List[Vulnerability], file_scanned: str):
        self.print_banner()
        self.console.print(f"\n[bold white]Scanned File:[/bold white] [yellow]{file_scanned}[/yellow]\n")

        if not findings:
            self.console.print(Panel("[bold green]✔ No security issues detected! Your code looks clean.[/bold green]", border_style="green"))
            return

        table = Table(title="Security Findings", show_header=True, header_style="bold magenta")
        table.add_column("Line", style="dim", width=8, justify="center")
        table.add_column("Severity", width=12, justify="center")
        table.add_column("Category", width=20)
        table.add_column("Description", style="white")

        for item in findings:
            sev_style = "bold red" if item.severity == "HIGH" else "bold yellow"
            severity_text = f"[{sev_style}]{item.severity}[/{sev_style}]"
            table.add_row(str(item.line), severity_text, item.category, item.description)

        self.console.print(table)
        self.console.print(f"\n[bold red]Total Issues Found: {len(findings)}[/bold red]\n")

# ==============================================================================
# 5. CLI ENTRYPOINT
# ==============================================================================
def main():
    if len(sys.argv) < 2:
        Console().print("[bold yellow]Usage:[/bold yellow] python aegis.py <path_to_python_file>")
        sys.exit(1)

    target_file = Path(sys.argv[1])
    engine = AegisEngine()
    reporter = RichReporter()

    findings = engine.scan_file(target_file)
    reporter.render_report(findings, str(target_file))
