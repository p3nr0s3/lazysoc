"""
MITRE ATT&CK Matrix Navigator & TTP Heatmap Engine for LazySOC.
Maps incident indicators, playbook phases, and threat categories to official MITRE Enterprise ATT&CK tactics, techniques, and mitigations.
"""

from typing import Dict, Any, List, Optional

MITRE_TACTICS_ORDER = [
    {"id": "TA0001", "name": "Initial Access", "icon": "door-open"},
    {"id": "TA0002", "name": "Execution", "icon": "play"},
    {"id": "TA0003", "name": "Persistence", "icon": "anchor"},
    {"id": "TA0004", "name": "Privilege Escalation", "icon": "shield-alert"},
    {"id": "TA0005", "name": "Defense Evasion", "icon": "eye-off"},
    {"id": "TA0006", "name": "Credential Access", "icon": "key"},
    {"id": "TA0007", "name": "Discovery", "icon": "search"},
    {"id": "TA0008", "name": "Lateral Movement", "icon": "arrow-left-right"},
    {"id": "TA0009", "name": "Collection", "icon": "hard-drive"},
    {"id": "TA0011", "name": "Command and Control", "icon": "radio"},
    {"id": "TA0010", "name": "Exfiltration", "icon": "upload-cloud"},
    {"id": "TA0040", "name": "Impact", "icon": "flame"},
]

TECHNIQUES_DATABASE = {
    # Initial Access
    "T1566": {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries send phishing messages with malicious attachments or links to gain execution on victim systems.",
        "detection": "Inspect inbound email headers, DMARC alignment, mail attachments with macro/executable payloads, and user click telemetry.",
        "mitigation": "M1049 - Antivirus/Antimalware, M1054 - Software Configuration, M1017 - User Training.",
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries attempt to exploit vulnerabilities in internet-facing services, web applications, or firewalls.",
        "detection": "Monitor web server error spikes (HTTP 500), anomalous inbound POST requests, and WAF inspection drops.",
        "mitigation": "M1051 - Update Software / Patch Management, M1050 - Web Application Firewall (WAF).",
    },
    # Execution
    "T1204": {
        "id": "T1204",
        "name": "User Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "An adversary relies on specific actions by a user (e.g. opening a malicious link or executable file) to gain execution.",
        "detection": "Monitor process creation spawned from email clients (outlook.exe, thunderbird) and browsers.",
        "mitigation": "M1038 - Execution Prevention, AppLocker / Software Restriction Policies.",
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries abuse PowerShell, bash, cmd.exe, Python, or VBScript to execute commands and scripts.",
        "detection": "Enable Script Block Logging (EID 4104), command-line process creation (EID 4688 / Sysmon EID 1).",
        "mitigation": "M1038 - Execution Prevention, Constrained Language Mode.",
    },
    # Persistence
    "T1505": {
        "id": "T1505",
        "name": "Server Software Component (Webshell)",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "description": "Adversaries abuse web servers by placing webshells (PHP, JSP, ASPX) in web root directories for covert access.",
        "detection": "Monitor file creation in web document roots (`/var/www/html/`, `C:\\inetpub\\wwwroot\\`) and anomalous child processes under w3wp.exe/httpd.",
        "mitigation": "M1024 - File Integrity Monitoring, Read-only web root permissions.",
    },
    "T1586": {
        "id": "T1586",
        "name": "Compromised Accounts",
        "tactic": "Persistence",
        "tactic_id": "TA0003",
        "description": "Adversaries obtain and use access to compromised legitimate enterprise accounts to establish persistence.",
        "detection": "Correlate impossible travel anomalies, sudden MFA device resets, and abnormal sign-in risk scores.",
        "mitigation": "M1032 - Multi-factor Authentication (FIDO2 / Conditional Access).",
    },
    # Credential Access
    "T1078": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries obtain and abuse credentials of existing enterprise accounts (compromised, default, or guest).",
        "detection": "Detect concurrent logins from disparate geolocations and elevated privilege usage without ticket authorization.",
        "mitigation": "M1026 - Privileged Account Management, Password rotation.",
    },
    "T1110": {
        "id": "T1110",
        "name": "Brute Force / Password Spraying",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries repeatedly test passwords against user accounts to acquire valid credentials.",
        "detection": "Track high volume failed logon spikes (Event ID 4625) across broad sets of usernames.",
        "mitigation": "M1036 - Account Use Policies, Smart lockout policies.",
    },
    # Command and Control
    "T1071": {
        "id": "T1071",
        "name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries communicate with external C2 servers using standard protocols like HTTP, HTTPS, or DNS to blend with normal traffic.",
        "detection": "Inspect beaconing jitter periodicity, anomalous outbound user-agents, and high-frequency queries to unrated domains.",
        "mitigation": "M1031 - Network Intrusion Prevention, DNS Sinkholing, TLS Inspection.",
    },
    # Exfiltration
    "T1041": {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "description": "Adversaries steal sensitive data by transmitting it over an established command and control channel.",
        "detection": "Monitor abnormal upload byte volume spikes during off-hours to unclassified foreign endpoints.",
        "mitigation": "M1030 - Network Segmentation, Data Loss Prevention (DLP).",
    },
    # Impact
    "T1486": {
        "id": "T1486",
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries encrypt data on target systems to interrupt availability of system and network resources.",
        "detection": "Detect high-frequency file rename/write events (`.locked`, `.crypto`), Volume Shadow Copy deletion (`vssadmin delete shadows`).",
        "mitigation": "M1053 - Immutable Data Backup, M1040 - EDR Anti-Ransomware Shield.",
    },
    "T1489": {
        "id": "T1489",
        "name": "Service Stop",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "description": "Adversaries stop or disable security agents and critical enterprise services (`sc stop`, `net stop`).",
        "detection": "Monitor Windows Service Control Manager Event ID 7036/7040 for terminated security services.",
        "mitigation": "M1026 - Privileged Account Management, Tamper Protection.",
    },
}


def get_mitre_matrix_data() -> Dict[str, Any]:
    """Returns the comprehensive MITRE ATT&CK Matrix structure and techniques."""
    # Group techniques under their respective tactics
    tactics_map = {t["name"]: [] for t in MITRE_TACTICS_ORDER}
    
    for tech_id, tech in TECHNIQUES_DATABASE.items():
        tactic_name = tech["tactic"]
        if tactic_name in tactics_map:
            tactics_map[tactic_name].append(tech)

    matrix_columns = []
    for t in MITRE_TACTICS_ORDER:
        matrix_columns.append({
            "tactic_id": t["id"],
            "name": t["name"],
            "icon": t["icon"],
            "techniques": tactics_map.get(t["name"], [])
        })

    return {
        "tactics": MITRE_TACTICS_ORDER,
        "matrix": matrix_columns,
        "techniques_count": len(TECHNIQUES_DATABASE),
    }


def analyze_mitre_coverage(iocs: List[Dict[str, Any]], active_playbook_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Correlates active IoCs and chosen Playbook with relevant MITRE ATT&CK techniques,
    generating an active heatmap of triggered tactics.
    """
    highlighted_techniques = set()

    # Correlation from IoC Types
    for item in iocs:
        itype = item.get("type", "").lower()
        verdict = item.get("verdict", "")
        if verdict in ("Malicious", "Suspicious"):
            if itype in ("ipv4", "ipv6", "domain"):
                highlighted_techniques.add("T1071")  # C2
            elif itype == "url":
                highlighted_techniques.add("T1566")  # Phishing
                highlighted_techniques.add("T1071")  # C2
            elif itype in ("md5", "sha1", "sha256"):
                highlighted_techniques.add("T1204")  # User Execution
                highlighted_techniques.add("T1059")  # Scripting

    # Correlation from Playbook
    playbook_tech_map = {
        "phishing": ["T1566", "T1204", "T1071", "T1078", "T1586"],
        "ransomware": ["T1486", "T1489", "T1059", "T1078"],
        "credential_theft": ["T1078", "T1110", "T1586"],
        "c2_exfil": ["T1071", "T1041"],
        "web_exploit": ["T1190", "T1505", "T1059"],
    }

    if active_playbook_id:
        norm_pb = active_playbook_id.lower().replace('pb-', '').replace('pb_', '')
        target_pb = norm_pb if norm_pb in playbook_tech_map else active_playbook_id
        if target_pb in playbook_tech_map:
            for t in playbook_tech_map[target_pb]:
                highlighted_techniques.add(t)

    covered_details = []
    for tid in highlighted_techniques:
        if tid in TECHNIQUES_DATABASE:
            covered_details.append(TECHNIQUES_DATABASE[tid])

    return {
        "active_techniques": list(highlighted_techniques),
        "details": covered_details,
        "total_active": len(highlighted_techniques),
    }


def export_mitre_navigator_layer(
    iocs: List[Dict[str, Any]],
    active_playbook_id: Optional[str] = None,
    layer_name: str = "LazySOC Incident TTP Heatmap",
) -> Dict[str, Any]:
    """
    Generates an official MITRE ATT&CK Navigator v4.5 compliant layer JSON.
    Can be directly uploaded into https://mitre-attack.github.io/attack-navigator/
    """
    coverage = analyze_mitre_coverage(iocs, active_playbook_id)
    active_tids = coverage.get("active_techniques", [])

    techniques_layer = []
    for tid in active_tids:
        tech_info = TECHNIQUES_DATABASE.get(tid, {})
        techniques_layer.append({
            "techniqueID": tid,
            "tactic": tech_info.get("tactic", "").lower().replace(" ", "-"),
            "score": 1,
            "color": "#ef4444",
            "comment": f"LazySOC Detection: {tech_info.get('name', 'Technique')} - {tech_info.get('description', '')[:80]}...",
            "enabled": True,
            "showSubtechniques": False,
        })

    return {
        "name": layer_name,
        "versions": {
            "attack": "15",
            "navigator": "4.5",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": f"Incident threat coverage layer generated by LazySOC. Active techniques: {len(active_tids)}",
        "filters": {
            "platforms": ["Windows", "Linux", "macOS", "IaaS", "Office Suite"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False
        },
        "hideDisabled": False,
        "techniques": techniques_layer,
        "gradient": {
            "colors": ["#00f2fe", "#ef4444"],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [
            {
                "label": "LazySOC Incident Triggered Technique",
                "color": "#ef4444"
            }
        ],
        "metadata": [
            {"name": "source", "value": "LazySOC Cyber Ops Platform"},
            {"name": "playbook", "value": active_playbook_id or "General Triage"}
        ]
    }

