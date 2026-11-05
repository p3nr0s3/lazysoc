"""Mail Health and Domain Spoofing Posture Checker for LazySOC."""

import re
from typing import Any, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

# Lookup states returned by MailHealthChecker._query()
OK = "ok"
NODATA = "nodata"      # domain exists, but has no record of this type
NXDOMAIN = "nxdomain"  # domain does not exist
ERROR = "error"        # timeout, SERVFAIL, refused, ... (we do not know the answer)

_SPF_ALL = re.compile(r"^([+\-~?]?)all$", re.IGNORECASE)


class MailHealthChecker:
    """Evaluates MX, SPF, and DMARC configurations to assess email spoofability."""

    def __init__(self, timeout: float = 4.0, resolver: Optional[Any] = None):
        if resolver is None:
            resolver = dns.resolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout
            resolver.nameservers = ['1.1.1.1', '8.8.8.8', '8.8.4.4', '1.0.0.1']
            # Without EDNS, large TXT answers (google.com, github.com, ...) come back
            # truncated and need a TCP retry, which many hosts/firewalls drop.
            resolver.use_edns(0, 0, 1232)
        self.resolver = resolver

    # ------------------------------------------------------------------ DNS
    def _query(self, name: str, rdtype: str) -> Tuple[str, Any]:
        """Returns (state, answers_or_error_message)."""
        try:
            return OK, self.resolver.resolve(name, rdtype)
        except dns.resolver.NoAnswer:
            return NODATA, None
        except dns.resolver.NXDOMAIN:
            return NXDOMAIN, None
        except dns.exception.Timeout:
            return ERROR, "DNS query timed out"
        except Exception as e:  # NoNameservers (SERVFAIL), YXDOMAIN, network errors...
            return ERROR, f"{type(e).__name__}: {str(e)[:120]}"

    @staticmethod
    def _txt_records(answers: Any) -> List[str]:
        return [b"".join(r.strings).decode("utf-8", errors="ignore").strip() for r in answers]

    # ------------------------------------------------------------- Main API
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Performs full Mail Health and anti-spoofing audit for a domain."""
        dom = domain.lower().strip()
        if "://" in dom:
            dom = dom.split("://")[1].split("/")[0]
        dom = dom.split("/")[0].split(":")[0].rstrip(".")

        mx_res = self._check_mx(dom)

        if mx_res.get("state") == NXDOMAIN:
            return {
                "domain": dom,
                "exists": False,
                "score": None,
                "rating": "NOT_FOUND",
                "verdict": "Domain does not exist (NXDOMAIN)",
                "mx": mx_res,
                "spf": {"has_spf": False, "record": None, "status": "N/A", "state": NXDOMAIN},
                "dmarc": {"has_dmarc": False, "record": None, "policy": "none", "status": "N/A", "state": NXDOMAIN},
                "issues": ["The domain does not exist, so there is no mail configuration to audit."],
                "dns_errors": [],
            }

        spf_res = self._check_spf(dom)
        dmarc_res = self._check_dmarc(dom)

        failed = [
            label for label, res in (("MX", mx_res), ("SPF", spf_res), ("DMARC", dmarc_res))
            if res.get("state") == ERROR
        ]
        if failed:
            return {
                "domain": dom,
                "exists": True,
                "score": None,
                "rating": "INCONCLUSIVE",
                "verdict": f"DNS lookup failed for {', '.join(failed)}. Result is incomplete, try again.",
                "mx": mx_res,
                "spf": spf_res,
                "dmarc": dmarc_res,
                "issues": [
                    f"{label}: {res.get('error', 'lookup failed')}"
                    for label, res in (("MX", mx_res), ("SPF", spf_res), ("DMARC", dmarc_res))
                    if res.get("state") == ERROR
                ],
                "dns_errors": failed,
            }

        score, rating, verdict, issues = self._calculate_health_score(mx_res, spf_res, dmarc_res)
        return {
            "domain": dom,
            "exists": True,
            "score": score,  # 0 to 100
            "rating": rating,  # 'PROTECTED', 'PARTIALLY_PROTECTED', 'VULNERABLE'
            "verdict": verdict,
            "mx": mx_res,
            "spf": spf_res,
            "dmarc": dmarc_res,
            "issues": issues,
            "dns_errors": [],
        }

    # ------------------------------------------------------------------- MX
    def _check_mx(self, domain: str) -> Dict[str, Any]:
        state, answers = self._query(domain, "MX")
        if state == ERROR:
            return {"has_mx": False, "provider": "Error", "records": [], "count": 0, "state": ERROR, "error": answers}
        if state != OK:
            return {"has_mx": False, "provider": "None", "records": [], "count": 0, "state": state}

        records = [{"priority": r.preference, "host": str(r.exchange).rstrip(".")} for r in answers]
        records.sort(key=lambda x: x["priority"])

        provider = "Custom / Private"
        hosts_str = " ".join(r["host"].lower() for r in records)
        if "google" in hosts_str or "aspmx" in hosts_str:
            provider = "Google Workspace"
        elif "outlook" in hosts_str or "microsoft" in hosts_str:
            provider = "Microsoft 365"
        elif "zoho" in hosts_str:
            provider = "Zoho Mail"
        elif "proton" in hosts_str:
            provider = "Proton Mail"
        elif "pphosted" in hosts_str or "proofpoint" in hosts_str:
            provider = "Proofpoint Security Gateway"
        elif "mimecast" in hosts_str:
            provider = "Mimecast Security Gateway"

        return {"has_mx": True, "provider": provider, "records": records, "count": len(records), "state": OK}

    # ------------------------------------------------------------------ SPF
    def _check_spf(self, domain: str) -> Dict[str, Any]:
        state, answers = self._query(domain, "TXT")
        if state == ERROR:
            return {"has_spf": False, "record": None, "status": "ERROR", "mechanism": "Unknown",
                    "state": ERROR, "error": answers}

        spf_records = [t for t in self._txt_records(answers)
                       if t.lower().startswith("v=spf1")] if state == OK else []

        if not spf_records:
            return {
                "has_spf": False,
                "record": None,
                "status": "MISSING",
                "mechanism": "None",
                "state": state,
                "details": "No SPF TXT record found. Attackers can forge mail from this domain.",
            }

        record = spf_records[0]
        mechanism = "Unknown"
        status = "ACCEPTABLE"
        for token in record.split()[1:]:
            m = _SPF_ALL.match(token)  # token match: 'include:x-all.example' must not count
            if not m:
                continue
            qualifier = m.group(1) or "+"
            if qualifier == "-":
                mechanism, status = "HardFail (-all)", "STRICT"
            elif qualifier == "~":
                mechanism, status = "SoftFail (~all)", "MODERATE"
            elif qualifier == "?":
                mechanism, status = "Neutral (?all)", "WEAK"
            else:
                mechanism, status = "Pass (+all)", "CRITICAL_RISK"
            break

        return {
            "has_spf": True,
            "record": record,
            "status": status,
            "mechanism": mechanism,
            "count": len(spf_records),
            "is_multiple": len(spf_records) > 1,
            "state": OK,
        }

    # ---------------------------------------------------------------- DMARC
    def _dmarc_lookup_names(self, domain: str) -> List[Tuple[str, bool]]:
        """_dmarc.<domain>, then parents down to two labels (RFC 7489 organizational fallback).

        Without a Public Suffix List this is an approximation; the result reports
        'inherited_from' so the analyst can see which record was used.
        """
        labels = domain.split(".")
        names = [(f"_dmarc.{domain}", False)]
        for i in range(1, max(len(labels) - 1, 1)):
            names.append((f"_dmarc.{'.'.join(labels[i:])}", True))
        return names

    def _check_dmarc(self, domain: str) -> Dict[str, Any]:
        for name, inherited in self._dmarc_lookup_names(domain):
            state, answers = self._query(name, "TXT")
            if state == ERROR:
                return {"has_dmarc": False, "record": None, "policy": "none", "status": "ERROR",
                        "state": ERROR, "error": answers}
            records = [t for t in self._txt_records(answers) if t.startswith("v=DMARC1")] if state == OK else []
            if records:
                return self._parse_dmarc(records[0], inherited_from=name if inherited else None)

        return {
            "has_dmarc": False,
            "record": None,
            "policy": "none",
            "status": "MISSING",
            "state": OK,
            "details": "No DMARC record found. Domain is vulnerable to direct sender spoofing.",
        }

    @staticmethod
    def _parse_dmarc(record: str, inherited_from: Optional[str]) -> Dict[str, Any]:
        tags = {}
        for part in record.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()

        policy = tags.get("p", "unknown").lower()
        # For a sub-domain that inherits the parent's record, 'sp' (if present) applies.
        effective = tags.get("sp", policy).lower() if inherited_from else policy

        rua_match = re.search(r"mailto:([^\s,;]+)", tags.get("rua", ""))
        pct_match = re.match(r"\d+", tags.get("pct", ""))
        pct = int(pct_match.group(0)) if pct_match else 100

        status = "VULNERABLE"
        if effective == "reject":
            status = "STRICT_PROTECTED"
        elif effective == "quarantine":
            status = "PROTECTED"
        elif effective == "none":
            status = "MONITORING_ONLY"

        details = f"Policy set to {effective.upper()} ({pct}% enforcement)"
        if inherited_from:
            details += f", inherited from {inherited_from}"

        return {
            "has_dmarc": True,
            "record": record,
            "policy": effective,
            "domain_policy": policy,
            "status": status,
            "reporting_email": rua_match.group(1) if rua_match else None,
            "pct": pct,
            "inherited_from": inherited_from,
            "state": OK,
            "details": details,
        }

    # -------------------------------------------------------------- Scoring
    def _calculate_health_score(
        self,
        mx: Dict[str, Any],
        spf: Dict[str, Any],
        dmarc: Dict[str, Any],
    ) -> Tuple[int, str, str, List[str]]:
        score = 0
        issues = []

        # MX component (20 pts)
        if mx.get("has_mx"):
            score += 20
        else:
            issues.append("No active MX records (Domain cannot receive emails).")

        # SPF component (35 pts)
        if spf.get("has_spf"):
            if spf.get("status") == "STRICT":
                score += 35
            elif spf.get("status") == "MODERATE":
                score += 28
                issues.append("SPF uses SoftFail (~all). Recommended: HardFail (-all).")
            elif spf.get("status") == "WEAK":
                score += 15
                issues.append("SPF uses Neutral (?all). Spoofed emails will not be blocked.")
            elif spf.get("status") == "CRITICAL_RISK":
                issues.append("CRITICAL: SPF uses +all, allowing any IP to send mail on your behalf!")
            else:
                issues.append("SPF record has no 'all' mechanism, so unauthorized senders are not rejected.")
            if spf.get("is_multiple"):
                issues.append("Multiple SPF records detected. This causes SPF PermError!")
                score = max(0, score - 15)
        else:
            issues.append("Missing SPF record. Anyone can forge emails from this domain.")

        # DMARC component (45 pts)
        if dmarc.get("has_dmarc"):
            pol = dmarc.get("policy")
            if pol == "reject":
                score += 45
            elif pol == "quarantine":
                score += 35
                issues.append("DMARC policy is quarantine. Consider upgrading to p=reject.")
            elif pol == "none":
                score += 15
                issues.append("DMARC policy is p=none (monitoring only). Direct spoofing is NOT blocked.")
            else:
                issues.append("DMARC record has no valid p= policy, so it is not enforced.")
            if dmarc.get("inherited_from"):
                issues.append(f"No DMARC record on this exact name; policy inherited from {dmarc['inherited_from']}.")
        else:
            issues.append("Missing DMARC record. Highly susceptible to brand impersonation and phishing.")

        if score >= 80:
            rating = "PROTECTED"
            verdict = "Strong Anti-Spoofing Posture"
        elif score >= 50:
            rating = "PARTIALLY_PROTECTED"
            verdict = "Partially Protected (Spoofing Possible)"
        else:
            rating = "VULNERABLE"
            verdict = "Vulnerable to Email Spoofing & Phishing"

        return score, rating, verdict, issues
