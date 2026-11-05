"""
Suspicious Script & Web Shell Scanner for LazySOC.
Inspects pasted scripts, webshells, server payloads, and command sequences
across PHP, PowerShell, Bash, Python, and VBScript.
"""

import re
from typing import Dict, Any, List, Optional
from core.parser import parse_raw_text

WEBSHELL_SIGNATURES = [
    (r"\b(c99shell|r57shell|b374k|wso_version|alfa\s*team|weevely|behinder|godzilla|china\s*chopper)\b", "Known Web Shell Family Name", "CRITICAL", "T1505.003"),
    (r"eval\s*\(\s*(gzinflate|gzdecode|gzuncompress|base64_decode|str_rot13)\s*\(", "Multi-Layer PHP Decompression & Code Execution", "CRITICAL", "T1027"),
    (r"eval\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)", "Direct User-Supplied Code Execution via eval()", "CRITICAL", "T1505.003"),
    (r"\bassert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)", "PHP Arbitrary Assertion / Dynamic Code Execution", "CRITICAL", "T1505.003"),
    (r"preg_replace\s*\(\s*['\"][^'\"]*\/e['\"]", "Deprecated PHP /e Regex Code Execution Vulnerability", "CRITICAL", "T1059"),
    (r"\$(?:_POST|_GET|_REQUEST|_COOKIE)\s*\[\s*['\"](?:cmd|command|exec|shell|pass|pwd|c)['\"]\s*\]", "Standard Web Shell Parameter Backdoor ($cmd / $exec)", "HIGH", "T1505.003"),
    (r"\b(system|exec|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\(\s*\$(?:_POST|_GET|_REQUEST)", "Direct User-Supplied System Command Execution", "CRITICAL", "T1059"),
    (r"\bfsockopen\s*\([^)]*\)\s*;\s*while\s*\(!feof", "PHP Socket-Based Interactive Reverse Shell", "CRITICAL", "T1059"),
]

POWERSHELL_SIGNATURES = [
    (r"(?:Invoke-Expression|IEX)\s*(?:\(New-Object\s+Net\.WebClient|\$|DownloadString)", "PowerShell In-Memory Download Cradle (IEX / WebClient)", "CRITICAL", "T1059.001"),
    (r"\[System\.Reflection\.Assembly\]::Load\s*\(", "PowerShell In-Memory Binary Assembly Loading", "CRITICAL", "T1620"),
    (r"Start-Process\s+[^-\n]*-WindowStyle\s+Hidden", "Hidden Window Process Spawning", "HIGH", "T1564.003"),
    (r"-ExecutionPolicy\s+Bypass\s+-NoProfile\s+-WindowStyle\s+Hidden", "Execution Policy Bypass with Stealthed Profile", "HIGH", "T1059.001"),
    (r"\[Convert\]::FromBase64String\s*\(", "Base64 Decoding Payload in PowerShell", "MEDIUM", "T1027"),
    (r"(?:Get-WmiObject|Get-CimInstance)\s+Win32_ShadowCopy", "Volume Shadow Copy Enumeration / Ransomware Preparation", "CRITICAL", "T1490"),
    (r"vssadmin(?:\.exe)?\s+delete\s+shadows", "Shadow Copy Destruction via vssadmin", "CRITICAL", "T1490"),
]

BASH_REVERSE_SIGNATURES = [
    (r"bash\s+-i\s+>&?\s*\/dev\/tcp\/[0-9.]+\/[0-9]+", "Classic Bash TCP Socket Interactive Reverse Shell", "CRITICAL", "T1059.004"),
    (r"(?:nc|netcat|ncat)\s+(?:-e|-c)\s+(?:\/bin\/(?:sh|bash)|cmd\.exe)", "Netcat Executable Reverse Shell Spawn", "CRITICAL", "T1059.004"),
    (r"mkfifo\s+\/tmp\/[a-z0-9_-]+\s*;\s*(?:cat|nc)", "Named Pipe (FIFO) Interactive Reverse Shell", "CRITICAL", "T1059.004"),
    (r"python(?:3)?\s+-c\s+['\"]import\s+socket,subprocess,os;.*pty\.spawn", "Python One-Liner Interactive PTY Reverse Shell", "CRITICAL", "T1059.006"),
    (r"socat\s+exec:['\"]?(?:\/bin\/sh|\/bin\/bash)['\"]?,\s*pty,\s*stderr", "Socat Encrypted / PTY Reverse Terminal", "HIGH", "T1059.004"),
    (r"curl\s+[^|\n]+\|\s*(?:bash|sh)", "Remote Script Piping Directly to Shell Execution", "HIGH", "T1105"),
]

DOWNLOAD_CRADLE_SIGNATURES = [
    (r"certutil(?:\.exe)?\s+-(?:urlcache|f)\s+-split", "Certutil Native Windows Binary File Download Cradle", "HIGH", "T1105"),
    (r"bitsadmin(?:\.exe)?\s+\/transfer", "BITSAdmin Background File Transfer Abuse", "HIGH", "T1105"),
    (r"mshta(?:\.exe)?\s+(?:http|javascript|vbscript):", "MSHTA Remote Script Protocol Execution", "CRITICAL", "T1218.005"),
    (r"regsvr32(?:\.exe)?\s+\/s\s+\/n\s+\/u\s+\/i:", "Squiblydoo Regsvr32 Remote SCT Scriptlet Execution", "CRITICAL", "T1218.010"),
    (r"rundll32(?:\.exe)?\s+javascript:", "Rundll32 JavaScript Protocol Handler Execution", "CRITICAL", "T1218.011"),
]


def scan_script_payload(payload: str) -> Dict[str, Any]:
    """
    Scans a raw script payload for web shells, dangerous execution primitives,
    reverse shell sockets, and LOLBAS download cradles.
    """
    if not payload or not payload.strip():
        return {
            "verdict": "CLEAN",
            "threat_score": 0,
            "threat_level": "INFO",
            "findings": [],
            "extracted_iocs": [],
            "mitre_ttps": [],
            "recommendations": ["No content provided."]
        }

    raw = payload.strip()
    findings: List[Dict[str, Any]] = []
    mitre_set = set()
    total_score = 0

    all_signature_groups = [
        ("Web Shell Indicators", WEBSHELL_SIGNATURES),
        ("PowerShell Evasion & Execution", POWERSHELL_SIGNATURES),
        ("Unix / Linux Reverse Shells", BASH_REVERSE_SIGNATURES),
        ("Download Cradles & LOLBAS Abuse", DOWNLOAD_CRADLE_SIGNATURES),
    ]

    for category, sig_list in all_signature_groups:
        for pattern, desc, severity, mitre in sig_list:
            matches = list(re.finditer(pattern, raw, re.IGNORECASE))
            if matches:
                sample_snippet = matches[0].group(0)
                if len(sample_snippet) > 80:
                    sample_snippet = sample_snippet[:80] + "..."

                score_map = {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
                points = score_map.get(severity, 10)
                total_score += points * len(matches)

                findings.append({
                    "category": category,
                    "description": desc,
                    "severity": severity,
                    "matches_count": len(matches),
                    "matched_snippet": sample_snippet,
                    "mitre_ttp": mitre
                })
                mitre_set.add(mitre)

    # Heuristic for base64 blocks
    b64_matches = re.findall(r"[A-Za-z0-9+/]{80,}={0,2}", raw)
    if b64_matches:
        findings.append({
            "category": "Obfuscation / Encoding",
            "description": f"Detected {len(b64_matches)} large Base64 blobs (>80 chars). Often conceals executable binaries or shellcode.",
            "severity": "HIGH",
            "matches_count": len(b64_matches),
            "matched_snippet": b64_matches[0][:60] + "...",
            "mitre_ttp": "T1027"
        })
        mitre_set.add("T1027")
        total_score += 20

    # Extract all indicators (IPs, URLs, Hashes)
    extracted = parse_raw_text(raw)
    extracted_iocs = [{"value": item.value, "type": item.ioc_type} for item in extracted]

    # Calculate final verdict
    if total_score >= 40:
        verdict = "MALICIOUS"
        threat_level = "CRITICAL" if total_score >= 60 else "HIGH"
    elif total_score >= 15:
        verdict = "SUSPICIOUS"
        threat_level = "MEDIUM"
    else:
        verdict = "CLEAN" if total_score == 0 else "SUSPICIOUS"
        threat_level = "LOW" if total_score > 0 else "INFO"

    # Prescriptive recommendations
    recommendations = []
    if any(f["mitre_ttp"] == "T1505.003" for f in findings):
        recommendations.append("Immediate Host Isolation: Suspected server web shell. Disconnect affected host from internal network.")
        recommendations.append("Audit Web Server Logs: Search for HTTP POST requests to this script URL to identify attacker IP and commands.")
    if any("Reverse Shell" in f["description"] for f in findings):
        recommendations.append("Terminate Active Socket: Check netstat / ss for active outgoing connections to the extracted attacker IP.")
    if any(f["mitre_ttp"] == "T1490" for f in findings):
        recommendations.append("Ransomware Alert: Shadow copy deletion attempted. Check running processes for file encryption routines.")
    if not recommendations:
        recommendations.append("No active malicious web shell or reverse shell signatures triggered.")

    return {
        "verdict": verdict,
        "threat_score": min(total_score, 100),
        "threat_level": threat_level,
        "findings_count": len(findings),
        "findings": findings,
        "extracted_iocs": extracted_iocs,
        "mitre_ttps": sorted(list(mitre_set)),
        "recommendations": recommendations,
        "script_length_chars": len(raw),
        "script_lines": len(raw.splitlines())
    }
