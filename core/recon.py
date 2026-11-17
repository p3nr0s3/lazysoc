"""Network Recon, RDAP/WHOIS, Shodan Exposure, and IP Geolocation module for LazySOC."""

import socket
import ipaddress
import base64
import hashlib
import concurrent.futures
from urllib.parse import quote, urlparse
from typing import Dict, Any, Optional, List
import requests
import dns.resolver
from core.parser import is_valid_ipv4, is_valid_ipv6
from core.config import SHODAN_INTERNETDB_URL


def is_private_ip(ip: str) -> bool:
    """Checks if an IP string is private, loopback, or non-routable."""
    try:
        ip_obj = ipaddress.ip_address(ip.strip())
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except Exception:
        return False


def resolve_ptr(ip: str) -> Optional[str]:
    """Resolves IP address to reverse DNS hostname (PTR record)."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def get_ip_geo(ip: str) -> Dict[str, Any]:
    """Retrieves Geolocation, ASN, and ISP for an IP address via IP-API."""
    if is_private_ip(ip):
        return {
            "success": False,
            "ip": ip,
            "error": "Private / RFC 1918 address (not routable on public internet)",
        }

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        resp = requests.get(url, timeout=5, headers={"User-Agent": "LazySOC-CyberSec/3.0"})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "success": True,
                    "ip": data.get("query", ip),
                    "country": data.get("country", "Unknown"),
                    "country_code": data.get("countryCode", "??"),
                    "city": data.get("city", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone", ""),
                    "isp": data.get("isp", "Unknown"),
                    "org": data.get("org", ""),
                    "asn": data.get("as", "Unknown"),
                }
        return {"success": False, "error": f"Lookup failed: {resp.text[:80]}"}
    except Exception as e:
        return {"success": False, "error": f"Network error: {str(e)}"}


def get_shodan_exposure(ip: str) -> Dict[str, Any]:
    """
    Queries Shodan's free, zero-key InternetDB API for open ports, CPEs,
    tags, hostnames, and known CVE vulnerabilities.
    """
    if is_private_ip(ip):
        return {
            "success": True,
            "found": False,
            "message": "Private / Internal IP range not indexed in Shodan InternetDB.",
            "ports": [],
            "vulns": [],
            "cpes": [],
            "tags": [],
        }

    try:
        url = f"{SHODAN_INTERNETDB_URL}/{ip}"
        resp = requests.get(url, timeout=5, headers={"User-Agent": "LazySOC-CyberSec/3.0"})
        if resp.status_code == 200:
            data = resp.json()
            return {
                "success": True,
                "found": True,
                "ip": data.get("ip", ip),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "cpes": data.get("cpes", []),
                "tags": data.get("tags", []),
                "hostnames": data.get("hostnames", []),
            }
        elif resp.status_code == 404:
            return {
                "success": True,
                "found": False,
                "message": "No open ports or active CVEs indexed in Shodan InternetDB.",
                "ports": [],
                "vulns": [],
                "cpes": [],
                "tags": [],
            }
        return {"success": False, "found": False, "error": f"Shodan returned status {resp.status_code}"}
    except Exception as e:
        return {"success": False, "found": False, "error": f"Shodan InternetDB error: {str(e)}"}


def get_rdap_whois(domain: str) -> Dict[str, Any]:
    """Queries ICANN's standardized RDAP service for domain registration data."""
    clean_domain = domain.lower().strip()
    if "://" in clean_domain:
        clean_domain = clean_domain.split("://")[1].split("/")[0]
    clean_domain = clean_domain.split("/")[0].split(":")[0]

    try:
        url = f"https://rdap.org/domain/{clean_domain}"
        resp = requests.get(url, timeout=6, headers={"Accept": "application/json", "User-Agent": "LazySOC-CyberSec/3.0"})
        if resp.status_code == 200:
            data = resp.json()

            # Extract registrar entity
            registrar = "Unknown"
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                registrar = item[3]
                                break
                    if registrar == "Unknown" and ent.get("handle"):
                        registrar = ent.get("handle")

            # Extract creation and expiration dates
            created = "Unknown"
            expires = "Unknown"
            updated = "Unknown"
            for ev in data.get("events", []):
                action = ev.get("eventAction", "")
                date = ev.get("eventDate", "")
                if action in ("registration", "registered"):
                    created = date[:10]
                elif action in ("expiration", "expired"):
                    expires = date[:10]
                elif action in ("last changed", "last update"):
                    updated = date[:10]

            # Nameservers
            nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", []) if isinstance(ns, dict)]

            # Status codes
            status = data.get("status", [])

            return {
                "success": True,
                "domain": clean_domain,
                "registrar": registrar,
                "created": created,
                "expires": expires,
                "updated": updated,
                "nameservers": nameservers,
                "status": status,
            }
        elif resp.status_code == 404:
            return {"success": False, "error": "Domain registration record not found in RDAP."}
        else:
            return {"success": False, "error": f"RDAP server responded with status {resp.status_code}"}
    except Exception as e:
        return {"success": False, "error": f"RDAP query failed: {str(e)}"}


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 32-bit (signed) — matching Shodan's http.favicon.hash."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed
    rounded = length & 0xFFFFFFFC
    for i in range(0, rounded, 4):
        k1 = (data[i] & 0xFF) | ((data[i + 1] & 0xFF) << 8) | ((data[i + 2] & 0xFF) << 16) | (data[i + 3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded + 2] & 0xFF) << 16
    if tail >= 2:
        k1 |= (data[rounded + 1] & 0xFF) << 8
    if tail >= 1:
        k1 |= data[rounded] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def get_favicon_intel(domain_or_url: str, timeout: float = 4.0) -> Dict[str, Any]:
    """
    Fetches website favicon.ico, computes MurmurHash3 & MD5 signatures,
    and generates pivot links for Shodan, FOFA, Censys, and ZoomEye.
    Enables detection of phishing replicas and uncovering CDN/WAF-masked origin IPs.
    """
    target = domain_or_url.strip().lower()
    if target.startswith("http://") or target.startswith("https://"):
        target = urlparse(target).netloc
    target = target.split("/")[0].split(":")[0]

    content = None
    fetched_url = None
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "image/x-icon,image/webp,image/apng,image/*,*/*;q=0.8",
    }
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}/favicon.ico"
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            if resp.status_code == 200 and resp.content and len(resp.content) > 30:
                content = resp.content
                fetched_url = url
                break
        except Exception:
            continue

    if not content:
        return {
            "found": False,
            "domain": target,
            "message": f"No favicon could be retrieved from {target}",
        }

    b64 = base64.encodebytes(content)
    mmh3 = _murmur3_32(b64)
    md5 = hashlib.md5(content).hexdigest()
    fofa_query = f'icon_hash="{mmh3}"'
    fofa_q = base64.b64encode(fofa_query.encode("utf-8")).decode("utf-8")

    return {
        "found": True,
        "domain": target,
        "favicon_url": fetched_url,
        "mmh3": mmh3,
        "md5": md5,
        "size_bytes": len(content),
        "pivots": {
            "Shodan": f"https://www.shodan.io/search?query=http.favicon.hash%3A{mmh3}",
            "FOFA": f"https://fofa.info/result?qbase64={quote(fofa_q)}",
            "ZoomEye": f"https://www.zoomeye.org/searchResult?q=iconhash%3A%22{mmh3}%22",
            "Censys": f"https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.md5_hash%3A%22{md5}%22",
        },
        "description": "MurmurHash3 signature matching Shodan http.favicon.hash. Use pivots to discover phishing clones and uncloak origin servers behind CDNs/Cloudflare.",
    }


def generate_lookalike_domains(domain: str) -> List[str]:
    """Generates typosquatting and lookalike domain permutations."""
    d = domain.lower().strip()
    if "." not in d:
        return []
    parts = d.split(".", 1)
    name, tld = parts[0], parts[1]

    candidates = set()
    # 1. Common TLD substitutions
    tlds = ["com", "net", "org", "co", "io", "biz", "info", "online"]
    for t in tlds:
        if t != tld:
            candidates.add(f"{name}.{t}")

    # 2. Omissions
    if len(name) > 3:
        for i in range(len(name)):
            candidates.add(f"{name[:i]}{name[i+1:]}.{tld}")

    # 3. Double letters / repetition
    for i in range(min(5, len(name))):
        candidates.add(f"{name[:i]}{name[i]}{name[i:]}.{tld}")

    # 4. Transposition
    for i in range(len(name) - 1):
        candidates.add(f"{name[:i]}{name[i+1]}{name[i]}{name[i+2:]}.{tld}")

    # 5. Phishing prefixes / hyphens
    prefixes = ["login-", "secure-", "auth-", "portal-", "verify-"]
    for p in prefixes:
        candidates.add(f"{p}{name}.{tld}")

    candidates.discard(d)
    return sorted(candidates)


def typosquat_triage(domain: str, max_checks: int = 15) -> List[Dict[str, Any]]:
    """
    Performs active DNS triage across lookalike domains to categorize them:
    - phishing-ready: Live A record AND active Mail Server (MX). High threat.
    - active-web: Live A record without MX.
    - dormant: Unregistered or offline.
    """
    candidates = generate_lookalike_domains(domain)[:max_checks]
    results = []

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    sys_ns = list(resolver.nameservers or [])
    fallback_ns = ["1.1.1.1", "8.8.8.8"]
    resolver.nameservers = sys_ns + [ns for ns in fallback_ns if ns not in sys_ns]

    def _check(cand: str) -> Dict[str, Any]:
        live_ips = []
        mail_mx = []
        try:
            ans_a = resolver.resolve(cand, "A")
            live_ips = [str(r) for r in ans_a]
        except Exception:
            pass

        try:
            ans_mx = resolver.resolve(cand, "MX")
            mail_mx = [str(r.exchange).rstrip(".") for r in ans_mx]
        except Exception:
            pass

        live = bool(live_ips)
        has_mail = bool(mail_mx)
        if live and has_mail:
            risk = "CRITICAL (Phishing-Ready)"
            status = "phishing-ready"
        elif live:
            risk = "MEDIUM (Active Web Host / Parked)"
            status = "active-web"
        else:
            risk = "LOW (Unregistered / Dormant)"
            status = "dormant"

        return {
            "domain": cand,
            "live": live,
            "has_mail": has_mail,
            "ips": live_ips[:3],
            "mx": mail_mx[:2],
            "risk": risk,
            "status": status,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(_check, candidates))

    order = {"phishing-ready": 0, "active-web": 1, "dormant": 2}
    results.sort(key=lambda x: order.get(x["status"], 9))
    return results


def perform_recon(target: str, include_extended: bool = True) -> Dict[str, Any]:
    """Unified network recon orchestrator for an IP address or Domain."""
    tgt = target.strip()
    is_ip = is_valid_ipv4(tgt) or is_valid_ipv6(tgt)

    if is_ip:
        ptr = resolve_ptr(tgt)
        geo = get_ip_geo(tgt)
        shodan = get_shodan_exposure(tgt)
        return {
            "target": tgt,
            "type": "ip",
            "ptr": ptr or "No PTR hostname configured",
            "geo": geo,
            "shodan": shodan,
        }
    else:
        # Domain target
        rdap = get_rdap_whois(tgt)
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(tgt)
        except Exception:
            pass

        geo = get_ip_geo(resolved_ip) if resolved_ip else None
        shodan = get_shodan_exposure(resolved_ip) if resolved_ip else None

        favicon = None
        if include_extended:
            favicon = get_favicon_intel(tgt)

        return {
            "target": tgt,
            "type": "domain",
            "resolved_ip": resolved_ip,
            "whois": rdap,
            "geo": geo,
            "shodan": shodan,
            "favicon": favicon,
        }
