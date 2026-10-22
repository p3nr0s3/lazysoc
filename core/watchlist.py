"""
Critical Tools Watchlist correlation for LazySOC.
Matches cyber news and CISA KEV entries against the internal & customer tool inventory
(data/watchlist.json) and checks deployed versions against NVD CPE version ranges.
"""

import json
import re
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from core.config import WATCHLIST_FILE, NVD_API_KEY
from core.cve import fetch_kev_catalog, fetch_nvd_cve
from core.database import get_cached_nvd_cve, save_cached_nvd_cve

CRITICALITY_WEIGHT = {"critical": 3, "high": 2, "normal": 1}
VENDOR_LEVEL_FACTOR = 0.5
RE_CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

STATUS_AFFECTED = "affected"
STATUS_NOT_AFFECTED = "not_affected"
STATUS_UNKNOWN = "unknown"
STATUS_PENDING = "pending"

_lock = threading.Lock()
_state: Dict[str, Any] = {"mtime": None, "assets": [], "error": None}


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def _term_pattern(terms: List[str], case_sensitive: bool) -> Optional[re.Pattern]:
    terms = [t for t in terms if t and t.strip()]
    if not terms:
        return None
    # Longest first so "FortiClient VPN" wins over "FortiClient" in the matched term list.
    alternation = "|".join(re.escape(t.strip()) for t in sorted(terms, key=len, reverse=True))
    return re.compile(rf"(?<![A-Za-z0-9])(?:{alternation})(?![A-Za-z0-9])", 0 if case_sensitive else re.IGNORECASE)


def _prepare_asset(raw: Dict[str, Any]) -> Dict[str, Any]:
    asset = dict(raw)
    asset["criticality"] = (asset.get("criticality") or "normal").lower()
    if asset["criticality"] not in CRITICALITY_WEIGHT:
        asset["criticality"] = "normal"
    asset["deployments"] = [d for d in asset.get("deployments", []) if d.get("owner")]
    asset["_product_re"] = _term_pattern(asset.get("aliases", []), case_sensitive=False)
    asset["_strict_re"] = _term_pattern(asset.get("strict_aliases", []), case_sensitive=True)
    asset["_vendor_re"] = _term_pattern(asset.get("vendor_aliases", []), case_sensitive=False)
    asset["_cpe"] = {c.lower() for c in asset.get("cpe", [])}
    return asset


def load_watchlist() -> List[Dict[str, Any]]:
    """Loads and compiles the watchlist, reloading automatically when the file changes."""
    with _lock:
        try:
            mtime = WATCHLIST_FILE.stat().st_mtime
        except OSError:
            _state.update({"mtime": None, "assets": [], "error": f"Watchlist file not found: {WATCHLIST_FILE.name}"})
            return []

        if _state["mtime"] == mtime:
            return _state["assets"]

        try:
            with open(WATCHLIST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            assets = [_prepare_asset(a) for a in data.get("assets", []) if a.get("id")]
            _state.update({"mtime": mtime, "assets": assets, "error": None})
        except Exception as e:
            _state.update({"mtime": mtime, "assets": [], "error": f"Invalid watchlist file: {e}"})
        return _state["assets"]


def _public_deployments(asset: Dict[str, Any], owner: Optional[str]) -> List[Dict[str, Any]]:
    deps = asset["deployments"]
    if owner:
        deps = [d for d in deps if d["owner"].lower() == owner.lower()]
    return [{"owner": d["owner"], "version": d.get("version", ""), "note": d.get("note", "")} for d in deps]


def _assets_for_owner(owner: Optional[str]) -> List[Dict[str, Any]]:
    assets = load_watchlist()
    if not owner:
        return assets
    return [a for a in assets if any(d["owner"].lower() == owner.lower() for d in a["deployments"])]


def get_watchlist_summary() -> Dict[str, Any]:
    """Returns owners and assets for the UI (without compiled regex internals)."""
    assets = load_watchlist()
    owners = sorted({d["owner"] for a in assets for d in a["deployments"]}, key=lambda o: (o != "Internal", o.lower()))
    return {
        "loaded": bool(assets),
        "error": _state["error"],
        "owners": owners,
        "total_assets": len(assets),
        "assets": [
            {
                "id": a["id"],
                "vendor": a.get("vendor", ""),
                "product": a.get("product", ""),
                "category": a.get("category", ""),
                "criticality": a["criticality"],
                "owners": sorted({d["owner"] for d in a["deployments"]}),
                "deployments": _public_deployments(a, None),
            }
            for a in assets
        ],
    }


def extract_cve_ids(text: str) -> List[str]:
    seen: List[str] = []
    for m in RE_CVE_ID.findall(text or ""):
        cve = m.upper()
        if cve not in seen:
            seen.append(cve)
    return seen


def match_text(text: str, owner: Optional[str] = None) -> List[Dict[str, Any]]:
    """Finds watchlist products (and, as a weaker signal, vendors) mentioned in free text."""
    if not text:
        return []

    matches: List[Dict[str, Any]] = []
    product_vendors = set()
    vendor_hits: Dict[str, Dict[str, Any]] = {}

    for asset in _assets_for_owner(owner):
        terms = set()
        for pattern in (asset["_product_re"], asset["_strict_re"]):
            if pattern:
                terms.update(m.group(0) for m in pattern.finditer(text))
        if terms:
            product_vendors.add(_norm(asset.get("vendor", "")))
            matches.append({
                "level": "product",
                "asset_id": asset["id"],
                "vendor": asset.get("vendor", ""),
                "product": asset.get("product", ""),
                "criticality": asset["criticality"],
                "terms": sorted(terms),
                "owners": sorted({d["owner"] for d in _public_deployments(asset, owner)}),
                "deployments": _public_deployments(asset, owner),
            })
            continue

        if asset["_vendor_re"]:
            vendor_terms = {m.group(0) for m in asset["_vendor_re"].finditer(text)}
            if vendor_terms:
                key = _norm(asset.get("vendor", ""))
                hit = vendor_hits.setdefault(key, {
                    "level": "vendor",
                    "asset_id": f"vendor:{key}",
                    "vendor": asset.get("vendor", ""),
                    "product": f"{asset.get('vendor', '')} (vendor disebut, produk tidak spesifik)",
                    "criticality": asset["criticality"],
                    "terms": set(),
                    "owners": set(),
                    "deployments": [],
                })
                hit["terms"].update(vendor_terms)
                hit["owners"].update(d["owner"] for d in _public_deployments(asset, owner))
                if CRITICALITY_WEIGHT[asset["criticality"]] > CRITICALITY_WEIGHT[hit["criticality"]]:
                    hit["criticality"] = asset["criticality"]

    for key, hit in vendor_hits.items():
        if key in product_vendors:
            continue  # a specific product of this vendor already matched
        hit["terms"] = sorted(hit["terms"])
        hit["owners"] = sorted(hit["owners"])
        matches.append(hit)

    matches.sort(key=lambda m: (m["level"] != "product", -CRITICALITY_WEIGHT[m["criticality"]], m["product"]))
    return matches


def priority_score(matches: List[Dict[str, Any]]) -> float:
    """Ranks an article by the most critical watchlist item it touches."""
    best = 0.0
    for m in matches:
        score = CRITICALITY_WEIGHT[m["criticality"]] * (1.0 if m["level"] == "product" else VENDOR_LEVEL_FACTOR)
        best = max(best, score)
    return best


# ------------------------------------------------------------------------------
# Version checks against NVD CPE configurations
# ------------------------------------------------------------------------------

def parse_version(value: Optional[str]) -> Optional[Tuple[int, ...]]:
    """Extracts a comparable numeric version, e.g. 'v7.4.8 build2795' -> (7, 4, 8)."""
    if not value:
        return None
    m = re.search(r"\d+(?:\.\d+)*", str(value))
    if not m:
        return None
    return tuple(int(p) for p in m.group(0).split("."))


def _cmp(a: Tuple[int, ...], b: Tuple[int, ...]) -> int:
    length = max(len(a), len(b))
    a = a + (0,) * (length - len(a))
    b = b + (0,) * (length - len(b))
    return (a > b) - (a < b)


def _vulnerable_cpe_matches(cve_obj: Dict[str, Any], asset_cpes: set) -> List[Dict[str, Any]]:
    entries = []
    for config in cve_obj.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for cpe_match in node.get("cpeMatch", []) or []:
                if not cpe_match.get("vulnerable"):
                    continue
                parts = (cpe_match.get("criteria") or "").split(":")
                if len(parts) < 6:
                    continue
                if f"{parts[3]}:{parts[4]}".lower() in asset_cpes:
                    entries.append({**cpe_match, "_version": parts[5]})
    return entries


def _version_in_entry(version: Tuple[int, ...], entry: Dict[str, Any]) -> bool:
    exact = entry.get("_version", "*")
    if exact not in ("*", "-", ""):
        exact_v = parse_version(exact)
        return exact_v is not None and _cmp(version, exact_v) == 0

    bounds = [
        ("versionStartIncluding", lambda c: c >= 0),
        ("versionStartExcluding", lambda c: c > 0),
        ("versionEndIncluding", lambda c: c <= 0),
        ("versionEndExcluding", lambda c: c < 0),
    ]
    for field, ok in bounds:
        bound = parse_version(entry.get(field))
        if bound is not None and not ok(_cmp(version, bound)):
            return False
    return True  # no bounds means every version is listed as vulnerable


def _describe_entry(entry: Dict[str, Any]) -> str:
    parts = []
    if entry.get("versionStartIncluding"):
        parts.append(f">= {entry['versionStartIncluding']}")
    if entry.get("versionStartExcluding"):
        parts.append(f"> {entry['versionStartExcluding']}")
    if entry.get("versionEndIncluding"):
        parts.append(f"<= {entry['versionEndIncluding']}")
    if entry.get("versionEndExcluding"):
        parts.append(f"< {entry['versionEndExcluding']}")
    if not parts:
        exact = entry.get("_version", "*")
        return "semua versi" if exact in ("*", "-", "") else f"= {exact}"
    return " dan ".join(parts)


def evaluate_deployments(asset: Dict[str, Any], cve_obj: Optional[Dict[str, Any]], owner: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns each deployment of an asset with affected / not_affected / unknown / pending status."""
    deployments = _public_deployments(asset, owner)
    if cve_obj is None:
        return [{**d, "status": STATUS_PENDING, "reason": "Data versi NVD belum diambil"} for d in deployments]

    entries = _vulnerable_cpe_matches(cve_obj, asset["_cpe"]) if asset["_cpe"] else []
    results = []
    for d in deployments:
        version = parse_version(d.get("version"))
        if not asset["_cpe"]:
            results.append({**d, "status": STATUS_UNKNOWN, "reason": "Produk belum punya pemetaan CPE di watchlist"})
        elif not entries:
            results.append({**d, "status": STATUS_UNKNOWN, "reason": "NVD belum mencantumkan konfigurasi CPE untuk produk ini"})
        elif version is None:
            ranges = "; ".join(sorted({_describe_entry(e) for e in entries}))
            results.append({**d, "status": STATUS_UNKNOWN, "reason": f"Versi tidak tercatat. Versi rentan: {ranges}"})
        else:
            hit = next((e for e in entries if _version_in_entry(version, e)), None)
            if hit:
                results.append({**d, "status": STATUS_AFFECTED, "reason": f"Versi {d['version']} masuk rentang rentan ({_describe_entry(hit)})"})
            else:
                ranges = "; ".join(sorted({_describe_entry(e) for e in entries}))
                results.append({**d, "status": STATUS_NOT_AFFECTED, "reason": f"Versi {d['version']} di luar rentang rentan ({ranges})"})
    return results


def _get_nvd_cve(cve_id: str, allow_fetch: bool) -> Optional[Dict[str, Any]]:
    cached = get_cached_nvd_cve(cve_id)
    if cached is not None or not allow_fetch:
        return cached
    cve_obj = fetch_nvd_cve(cve_id)
    if cve_obj is not None:
        save_cached_nvd_cve(cve_id, cve_obj)
    return cve_obj


def _assets_in_cve(cve_obj: Dict[str, Any], assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [a for a in assets if a["_cpe"] and _vulnerable_cpe_matches(cve_obj, a["_cpe"])]


def _summarize_statuses(asset_results: List[Dict[str, Any]]) -> str:
    statuses = {d["status"] for a in asset_results for d in a["deployments"]}
    for status in (STATUS_AFFECTED, STATUS_PENDING, STATUS_UNKNOWN, STATUS_NOT_AFFECTED):
        if status in statuses:
            return status
    return STATUS_UNKNOWN


def check_cve_impact(cve_id: str, owner: Optional[str] = None, extra_asset_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Checks one CVE against the watchlist using its NVD CPE configuration."""
    cve_id = cve_id.strip().upper()
    if not RE_CVE_ID.fullmatch(cve_id):
        return {"cve_id": cve_id, "found": False, "error_type": "INVALID_ID", "error": "Format CVE ID tidak valid."}

    cve_obj = _get_nvd_cve(cve_id, allow_fetch=True)
    if cve_obj is None:
        return {"cve_id": cve_id, "found": False, "error": "CVE tidak ditemukan di NVD atau NVD tidak dapat dihubungi."}

    assets = _assets_for_owner(owner)
    matched = _assets_in_cve(cve_obj, assets)
    if extra_asset_ids:
        matched += [a for a in assets if a["id"] in extra_asset_ids and a not in matched]

    asset_results = [
        {
            "asset_id": a["id"],
            "vendor": a.get("vendor", ""),
            "product": a.get("product", ""),
            "criticality": a["criticality"],
            "deployments": evaluate_deployments(a, cve_obj, owner),
        }
        for a in matched
    ]
    descriptions = cve_obj.get("descriptions", [])
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    return {
        "cve_id": cve_id,
        "found": True,
        "description": description,
        "published": (cve_obj.get("published") or "")[:10],
        "overall_status": _summarize_statuses(asset_results) if asset_results else STATUS_NOT_AFFECTED,
        "assets": asset_results,
    }


def _kev_matches_asset(kev: Dict[str, Any], asset: Dict[str, Any]) -> bool:
    vendor = _norm(kev.get("vendorProject", ""))
    product = _norm(kev.get("product", ""))
    for spec in asset.get("kev", []) or []:
        spec_vendor = _norm(spec.get("vendor", ""))
        spec_product = _norm(spec.get("product", ""))
        if spec_vendor and spec_vendor in vendor and (not spec_product or spec_product in product):
            return True
    return False


def get_kev_exposure(owner: Optional[str] = None, since_days: int = 365, max_lookups: Optional[int] = None) -> Dict[str, Any]:
    """Lists CISA KEV entries that hit watchlist products, with per-deployment version status."""
    assets = [a for a in _assets_for_owner(owner) if a.get("kev")]
    if max_lookups is None:
        max_lookups = 30 if NVD_API_KEY else 5  # NVD allows 5 req/30s without a key

    catalog = fetch_kev_catalog()
    cutoff = (datetime.now() - timedelta(days=since_days)).strftime("%Y-%m-%d") if since_days > 0 else ""

    items = []
    lookups_left = max_lookups
    pending = 0
    for kev in catalog:
        if cutoff and kev.get("dateAdded", "") < cutoff:
            continue
        hit_assets = [a for a in assets if _kev_matches_asset(kev, a)]
        if not hit_assets:
            continue

        cve_id = kev.get("cveID", "")
        cve_obj = _get_nvd_cve(cve_id, allow_fetch=False)
        if cve_obj is None and lookups_left > 0:
            cve_obj = _get_nvd_cve(cve_id, allow_fetch=True)
            lookups_left -= 1

        asset_results = [
            {
                "asset_id": a["id"],
                "vendor": a.get("vendor", ""),
                "product": a.get("product", ""),
                "criticality": a["criticality"],
                "deployments": evaluate_deployments(a, cve_obj, owner),
            }
            for a in hit_assets
        ]
        overall = _summarize_statuses(asset_results)
        if overall == STATUS_PENDING:
            pending += 1

        items.append({
            "cve_id": cve_id,
            "vendor_project": kev.get("vendorProject", ""),
            "product": kev.get("product", ""),
            "name": kev.get("vulnerabilityName", ""),
            "description": kev.get("shortDescription", ""),
            "date_added": kev.get("dateAdded", ""),
            "due_date": kev.get("dueDate", ""),
            "ransomware": kev.get("knownRansomwareCampaignUse", "Unknown") == "Known",
            "required_action": kev.get("requiredAction", ""),
            "overall_status": overall,
            "criticality": max((a["criticality"] for a in hit_assets), key=lambda c: CRITICALITY_WEIGHT[c]),
            "assets": asset_results,
        })

    status_rank = {STATUS_AFFECTED: 0, STATUS_PENDING: 1, STATUS_UNKNOWN: 2, STATUS_NOT_AFFECTED: 3}
    # Stable sorts: newest first inside each status / criticality bucket.
    items.sort(key=lambda i: i["date_added"], reverse=True)
    items.sort(key=lambda i: (status_rank[i["overall_status"]], -CRITICALITY_WEIGHT[i["criticality"]]))

    return {
        "owner": owner or "all",
        "since_days": since_days,
        "kev_available": bool(catalog),
        "total": len(items),
        "affected": sum(1 for i in items if i["overall_status"] == STATUS_AFFECTED),
        "pending_version_checks": pending,
        "items": items,
    }
