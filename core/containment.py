"""
Containment & Remediation Script Generator for LazySOC.
Generates ready-to-run CLI commands, firewall blocklists, and host isolation scripts
for Palo Alto PAN-OS, Fortinet FortiOS, Cisco ASA, Linux iptables/nftables,
Windows Defender / PowerShell, and EDR agents (CrowdStrike / Defender).
"""

from typing import List, Dict, Any, Optional
import re


def _sanitize_label(val: str) -> str:
    """Sanitizes an indicator to be used safely in CLI object names."""
    return re.sub(r"[^a-zA-Z0-9_\.-]", "_", val).strip("_")


def generate_containment_scripts(
    iocs: List[Dict[str, Any]],
    rule_name: str = "LAZYSOC_BLOCK",
    zone: str = "untrust",
) -> Dict[str, Any]:
    """
    Generates ready-to-run firewall blocklists and endpoint containment commands
    categorized by platform based on provided triage indicators.
    """
    ips = []
    domains = []
    hashes = []

    for item in iocs:
        val = item.get("ioc") or item.get("value") or ""
        itype = (item.get("type") or item.get("ioc_type") or "").lower()
        verdict = (item.get("verdict") or "").lower()

        # If verdict filter is present, prioritize malicious/suspicious, or take all if none marked
        if not val:
            continue

        if itype in ("ipv4", "ipv6"):
            if not item.get("is_private") and not val.startswith(("10.", "192.168.", "172.16.")):
                ips.append(val)
        elif itype == "domain":
            domains.append(val)
        elif itype == "url":
            # Extract domain from URL
            d = val.replace("hxxps://", "").replace("hxxp://", "").replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if d and d not in domains:
                domains.append(d)
        elif itype in ("md5", "sha1", "sha256"):
            hashes.append(val)

    # 1. PALO ALTO PAN-OS CLI
    palo_lines = [
        f"# Palo Alto PAN-OS CLI Blocklist ({len(ips)} IPs, {len(domains)} Domains)",
        "configure",
    ]
    palo_obj_names = []
    for ip in ips:
        lbl = f"BL_{_sanitize_label(ip)}"
        palo_obj_names.append(lbl)
        palo_lines.append(f'set address "{lbl}" ip-netmask "{ip}/32" description "LazySOC Malicious Indicator"')
    for dom in domains:
        lbl = f"BL_{_sanitize_label(dom)}"
        palo_obj_names.append(lbl)
        palo_lines.append(f'set address "{lbl}" fqdn "{dom}" description "LazySOC Malicious FQDN"')

    if palo_obj_names:
        palo_lines.append(f'set address-group "{rule_name}_GRP" static [ {" ".join(palo_obj_names)} ]')
        palo_lines.append(
            f'set rulebase security rules "DROP_{rule_name}" to "{zone}" from any destination "{rule_name}_GRP" application any service any action drop log-start yes'
        )
    palo_lines.extend(["commit", "exit"])

    # 2. FORTINET FORTIOS CLI
    forti_lines = [
        f"# Fortinet FortiOS CLI Configuration ({len(ips)} IPs, {len(domains)} Domains)",
        "config firewall address",
    ]
    forti_obj_names = []
    for ip in ips:
        lbl = f"BL_{_sanitize_label(ip)}"
        forti_obj_names.append(lbl)
        forti_lines.append(f'    edit "{lbl}"')
        forti_lines.append(f"        set subnet {ip} 255.255.255.255")
        forti_lines.append('        set comment "LazySOC Malicious IoC"')
        forti_lines.append("    next")
    for dom in domains:
        lbl = f"BL_{_sanitize_label(dom)}"
        forti_obj_names.append(lbl)
        forti_lines.append(f'    edit "{lbl}"')
        forti_lines.append("        set type fqdn")
        forti_lines.append(f'        set fqdn "{dom}"')
        forti_lines.append('        set comment "LazySOC Malicious FQDN"')
        forti_lines.append("    next")
    forti_lines.append("end")

    if forti_obj_names:
        forti_lines.append("config firewall addrgrp")
        forti_lines.append(f'    edit "{rule_name}_GRP"')
        forti_lines.append(f'        set member {" ".join([f"{name}" for name in forti_obj_names])}')
        forti_lines.append("    next")
        forti_lines.append("end")

    # 3. CISCO ASA / FIREPOWER CLI
    cisco_lines = [
        f"# Cisco ASA / Firepower CLI Commands ({len(ips)} IPs)",
    ]
    for ip in ips:
        lbl = f"BL_{_sanitize_label(ip)}"
        cisco_lines.append(f"object network {lbl}")
        cisco_lines.append(f" host {ip}")
        cisco_lines.append(f" description LazySOC_Threat_Triage")
    if ips:
        cisco_lines.append(f"object-group network {rule_name}_GRP")
        for ip in ips:
            lbl = f"BL_{_sanitize_label(ip)}"
            cisco_lines.append(f" network-object object {lbl}")
        cisco_lines.append(f"access-list OUTSIDE_IN line 1 deny ip any object-group {rule_name}_GRP")
        cisco_lines.append(f"access-list INSIDE_OUT line 1 deny ip any object-group {rule_name}_GRP")

    # 4. LINUX IPTABLES & NFTABLES
    iptables_lines = [
        f"#!/usr/bin/env bash",
        f"# Linux iptables / nftables Emergency Containment ({len(ips)} IPs)",
        f"set -e",
    ]
    for ip in ips:
        iptables_lines.append(f"iptables -I INPUT -s {ip} -j DROP -m comment --comment 'LazySOC-Block'")
        iptables_lines.append(f"iptables -I OUTPUT -d {ip} -j DROP -m comment --comment 'LazySOC-Block'")
        iptables_lines.append(f"iptables -I FORWARD -s {ip} -j DROP -m comment --comment 'LazySOC-Block'")
        iptables_lines.append(f"iptables -I FORWARD -d {ip} -j DROP -m comment --comment 'LazySOC-Block'")

    # 5. WINDOWS DEFENDER / POWERSHELL NETWORK BLOCK
    win_fw_lines = [
        f"# PowerShell Windows Advanced Firewall Block Rules ({len(ips)} IPs)",
        f"# Run in elevated Administrator PowerShell",
    ]
    for ip in ips:
        win_fw_lines.append(
            f'New-NetFirewallRule -DisplayName "LazySOC Block Outbound - {ip}" -Direction Outbound -Action Block -RemoteAddress "{ip}" -Description "Malicious C2 Blocked by LazySOC"'
        )
        win_fw_lines.append(
            f'New-NetFirewallRule -DisplayName "LazySOC Block Inbound - {ip}" -Direction Inbound -Action Block -RemoteAddress "{ip}" -Description "Malicious Ingress Blocked by LazySOC"'
        )

    # 6. EDR & HOST ISOLATION SCRIPTS
    edr_lines = [
        f"# Endpoint Detection & Response (EDR) Remediation & Containment Snippets",
        "",
        "# [Option A] Microsoft Defender for Endpoint - Null Route via PowerShell (Instant C2 Severing):",
    ]
    for ip in ips:
        edr_lines.append(f'route add {ip} mask 255.255.255.255 127.0.0.1 metric 1 -p')
    
    edr_lines.extend([
        "",
        "# [Option B] CrowdStrike Falcon Real Time Response (RTR):",
        "# 1. Isolate target host from cloud console:",
        "#    isolate <device_id>",
        "# 2. Kill malicious process running by PID:",
        "#    kill <target_pid>",
        "",
        "# [Option C] Emergency Host Disconnect (Complete Network Cut):",
        "# PowerShell (Disable all network adapters):",
        'Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Disable-NetAdapter -Confirm:$false',
        "",
        "# Linux Emergency Interface Down:",
        "ip link set eth0 down || ifconfig eth0 down",
    ])

    # 7. HASH BAN LIST (FOR EDR CUSTOM INDICATORS)
    hash_lines = [
        f"# Hash Indicators for EDR Blacklist ({len(hashes)} Hashes)",
    ]
    for h in hashes:
        hash_lines.append(f"{h}")

    # 8. ABUSE TAKEDOWN NOTICE (FOR HOSTING / REGISTRAR ESCALATION)
    primary_target = domains[0] if domains else (ips[0] if ips else "malicious-indicator.local")
    takedown_dossier = generate_takedown_dossier(
        target=primary_target,
        threat_type="Malicious Infrastructure / Phishing & C2",
        evidence_notes=f"Identified {len(ips)} malicious IPs, {len(domains)} malicious domains, and {len(hashes)} malware payload hashes.",
        ip_address=ips[0] if ips else None,
    )

    return {
        "palo_alto": "\n".join(palo_lines),
        "fortinet": "\n".join(forti_lines),
        "cisco_asa": "\n".join(cisco_lines),
        "iptables": "\n".join(iptables_lines),
        "windows_firewall": "\n".join(win_fw_lines),
        "edr_isolation": "\n".join(edr_lines),
        "hash_blocklist": "\n".join(hash_lines),
        "takedown": takedown_dossier["body_text"],
        "stats": {
            "total_ips": len(ips),
            "total_domains": len(domains),
            "total_hashes": len(hashes),
        },
    }


def generate_takedown_dossier(
    target: str,
    threat_type: str = "Phishing & Credential Harvester",
    brand_targeted: Optional[str] = None,
    evidence_notes: Optional[str] = None,
    ip_address: Optional[str] = None,
    asn_info: Optional[str] = None,
    abuse_contacts: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Generates a formal, RFC-compliant Abuse Takedown Dossier & Notification Email
    ready for transmission to hosting providers, domain registrars, and CERT/CSIRTs.
    """
    clean_tgt = target.strip()
    if clean_tgt.startswith("http://") or clean_tgt.startswith("https://"):
        clean_tgt = clean_tgt.split("://", 1)[1]
    clean_tgt = clean_tgt.split("/")[0].split(":")[0]

    contacts = list(abuse_contacts or [])
    if not contacts:
        contacts = ["abuse@registrar.com", "abuse@hosting-provider.com"]

    contact_str = ", ".join(contacts)
    brand_str = brand_targeted or "Corporate Enterprise & Public Users"
    evidence_str = (
        evidence_notes
        or "Active weaponized portal impersonating brand assets to harvest user credentials and bypass authentication."
    )
    ip_str = ip_address or "Resolved Network Edge"
    asn_str = asn_info or "Hosting Network Operator"

    subject = f"[URGENT ABUSE TAKEDOWN] Malicious Infrastructure Notice — {clean_tgt}"

    plain_lines = [
        f"To: {contact_str}",
        f"Subject: {subject}",
        "Importance: High / Urgent",
        "Classification: TLP:CLEAR / LAWFUL DEFENSIVE NOTICE",
        "",
        "Dear Network Abuse Operations and Trust & Safety Team,",
        "",
        "Our Security Operations Center (SOC) has identified malicious cyber infrastructure actively operating within your managed network and IP / domain delegation.",
        "",
        "We formally request your immediate assistance to terminate this abusive service and mitigate ongoing harm to internet users.",
        "",
        "================================================================================",
        "                            TECHNICAL INCIDENT DOSSIER",
        "================================================================================",
        f"Target Indicator   : {clean_tgt}",
        f"Threat Category    : {threat_type}",
        f"Targeted Entity    : {brand_str}",
        f"Associated IP      : {ip_str}",
        f"Network ASN / ISP  : {asn_str}",
        "",
        "Incident Description & Evidence:",
        f"{evidence_str}",
        "",
        "================================================================================",
        "                            REQUIRED MITIGATION ACTIONS",
        "================================================================================",
        "1. IMMEDIATE SUSPENSION: Disable DNS resolution, null-route the target IP, or suspend hosting service for the offending customer account.",
        "2. LOG PRESERVATION: Preserve server access logs, origin IP connections, and registrant payment/account telemetry for law enforcement referral under applicable cybercrime statutes.",
        "3. CONFIRMATION: Provide written confirmation once the abusive infrastructure has been decommissioned.",
        "",
        "Thank you for your prompt cooperation in maintaining internet trust and safety.",
        "",
        "Respectfully,",
        "Security Operations Center (SOC) / Threat Incident Response Team",
        "Automated via LazySOC Threat Intelligence Workbench",
    ]

    body_text = "\n".join(plain_lines)

    return {
        "success": True,
        "target": clean_tgt,
        "threat_type": threat_type,
        "subject": subject,
        "abuse_contacts": contacts,
        "brand_targeted": brand_str,
        "associated_ip": ip_str,
        "asn_info": asn_str,
        "body_text": body_text,
    }
