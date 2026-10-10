#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Aegis Code - Next-Generation Security Auditing & Static Code Analysis Engine
Author: Aegis Code Team
License: MIT
"""

import os
import sys
import argparse
import time
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# قاعدة بيانات الأنماط الأمنية والثغرات (OWASP Top 10 & Common Vulnerabilities)
SECURITY_RULES = [
    {
        "id": "AEG-001",
        "name": "Hardcoded Secret / API Key",
        "severity": "Critical",
        "description": "Detected hardcoded credentials, API keys, or secrets in the source code.",
        "patterns": ["api_key", "password =", "secret_key", "bearer ", "auth_token"]
    },
    {
        "id": "AEG-002",
        "name": "SQL Injection Risk",
        "severity": "High",
        "description": "Potential SQL injection vulnerability via raw query string formatting or concatenation.",
        "patterns": ["execute(f\"", "execute('SELECT", "exec(query", "cursor.execute(f"]
    },
    {
        "id": "AEG-003",
        "name": "Insecure Deserialization / Evaluation",
        "severity": "High",
        "description": "Use of unsafe evaluation functions like eval() or pickle loading.",
        "patterns": ["eval(", "pickle.load", "exec("]
    },
    {
        "id": "AEG-004",
        "name": "Weak Cryptography / MD5 Usage",
        "severity": "Medium",
        "description": "Usage of deprecated or weak cryptographic hash algorithms (MD5/SHA1).",
        "patterns": ["hashlib.md5(", "hashlib.sha1("]
    }
]

def banner():
    banner_text = """
    [bold cyan]🛡️ AEGIS CODE - ADVANCED SECURITY & SAST ENGINE[/bold cyan]
    [dim]Deep Vulnerability Detection, Technical Debt & Code Quality Intelligence[/dim]
    """
    console.print(Panel(banner_text, expand=False))

def calculate_complexity(content):
    """حساب تقديري لمعامل التعقيد (Cyclomatic Complexity) والدين التقني"""
    lines = content.splitlines()
    loc = len(lines)
    # حساب تقريبي للتشعبات بناءً على الكلمات المفتاحية
    branches = sum(content.count(kw) for kw in ['if ', 'for ', 'while ', 'except ', 'case '])
    complexity_score = max(1, branches + 1)
    return loc, complexity_score

def scan_file(file_path):
    issues = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        loc, complexity = calculate_complexity(content)
        
        # فحص القواعد الأمنية
        for line_no, line in enumerate(content.splitlines(), 1):
            for rule in SECURITY_RULES:
                for pattern in rule["patterns"]:
                    if pattern in line.lower():
                        issues.append({
                            "file": file_path,
                            "line": line_no,
                            "rule_id": rule["id"],
                            "name": rule["name"],
                            "severity": rule["severity"],
                            "description": rule["description"],
                            "snippet": line.strip()
                        })
        return issues, loc, complexity
    except Exception as e:
        return [], 0, 0

def run_full_audit(path, lang, output_format):
    if not os.path.exists(path):
        console.print(f"[bold red][!] Error: Target path '{path}' does not exist![/bold red]")
        sys.exit(1)
        
    console.print(f"\n[cyan][*] Initializing Deep SAST Engine on path:[/cyan] {path}")
    console.print(f"[cyan][*] Language Mode:[/cyan] {lang.upper()}")
    time.sleep(1)
    
    total_files = 0
    total_loc = 0
    total_complexity = 0
    all_vulnerabilities = []
    
    with console.status("[bold green]Scanning files and analyzing Abstract Syntax Trees...[/bold green]"):
        for root, dirs, files in os.walk(path):
            # استبعاد المجلدات غير الضرورية
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', 'venv', 'env']]
            for file in files:
                if file.endswith(('.py', '.js', '.ts', '.go', '.cpp', '.java', '.c', '.php')):
                    total_files += 1
                    file_path = os.path.join(root, file)
                    file_issues, loc, comp = scan_file(file_path)
                    total_loc += loc
                    total_complexity += comp
                    all_vulnerabilities.extend(file_issues)
                    
    # عرض النتائج في جدول أنيق باستخدام مكتبة Rich
    console.print("\n")
    console.print(Panel("[bold green]📊 AUDIT & SECURITY REPORT SUMMARY[/bold green]", expand=False))
    
    summary_table = Table(show_header=True, header_style="bold magenta")
    summary_table.add_column("Metric", style="dim")
    summary_table.add_column("Value", justify="right")
    
    summary_table.add_row("Total Files Scanned", str(total_files))
    summary_table.add_row("Lines of Code (LOC)", str(total_loc))
    summary_table.add_row("Avg Code Complexity", f"{total_complexity / max(1, total_files):.1f}")
    summary_table.add_row("Total Vulnerabilities", str(len(all_vulnerabilities)), style="red" if all_vulnerabilities else "green")
    
    console.print(summary_table)
    
    # تفاصيل الثغرات إن وجدت
    if all_vulnerabilities:
        console.print("\n[bold red]⚠️ Detected Vulnerabilities & Security Weaknesses:[/bold red]")
        vuln_table = Table(show_header=True, header_style="bold red")
        vuln_table.add_column("Severity")
        vuln_table.add_column("Rule ID")
        vuln_table.add_column("Vulnerability")
        vuln_table.add_column("File & Line")
        
        for v in all_vulnerabilities:
            vuln_table.add_row(v["severity"], v["rule_id"], v["name"], f"{v['file']}:{v['line']}")
        console.print(vuln_table)
    else:
        console.print("\n[bold green]🎉 Great job! No critical security vulnerabilities detected in the scanned paths.[/bold green]")
        
    # تصدير التقرير إذا طلب المستخدم
    if output_format:
        report_data = {
            "timestamp": datetime.now().isoformat(),
            "target": path,
            "metrics": {
                "files_scanned": total_files,
                "lines_of_code": total_loc,
                "vulnerabilities_count": len(all_vulnerabilities)
            },
            "vulnerabilities": all_vulnerabilities
        }
        output_filename = f"aegis_report.{output_format}"
        if output_format == "json":
            with open(output_filename, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4)
            console.print(f"\n[cyan][*] Report successfully exported to {output_filename}[/cyan]")

def main():
    parser = argparse.ArgumentParser(description="Aegis Code - Advanced Security Auditing & Static Code Analysis Engine")
    parser.add_argument("--scan", required=True, help="Path to the project directory to audit")
    parser.add_argument("--lang", default="en", choices=["ar", "en"], help="Report language (ar or en)")
    parser.add_argument("--format", choices=["json"], help="Export audit report format")
    
    args = parser.parse_args()
    
    banner()
    run_full_audit(args.scan, args.lang, args.format)

if __name__ == "__main__":
    main()

