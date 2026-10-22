"""FastAPI Server for LazySOC Cyber Threat Triage & SOC Workbench."""

import os
import uvicorn
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from pathlib import Path
import json

from core.config import BASE_DIR, CACHE_TTL_HOURS, CORS_ALLOWED_ORIGINS
from core.parser import parse_raw_text, parse_uploaded_file, IoCItem
from core.key_manager import (
    KeyManager,
    SERVICE_VT,
    SERVICE_ABUSE,
)
from core.clients.virustotal import VirusTotalClient
from core.clients.abuseipdb import AbuseIPDBClient
from core.mail_health import MailHealthChecker
from core.recon import perform_recon
from core.email_analyzer import EmailAnalyzer
from core.engine import (
    EnrichmentEngine,
    VERDICT_MALICIOUS,
    VERDICT_SUSPICIOUS,
    VERDICT_CLEAN,
    VERDICT_UNKNOWN,
)
from core.database import (
    get_all_cached_iocs,
    clear_cache,
    delete_cache_entry,
    get_cache_stats,
    get_scan_history,
)
from core.exporter import export_to_csv, export_to_json
from core.feed import get_cyber_news, get_article_by_link
from core.cve import query_cve
from core.watchlist import get_watchlist_summary, get_kev_exposure, check_cve_impact
from core.watchlist_import import (
    WatchlistImportError,
    import_watchlist,
    save_watchlist,
    read_current_watchlist,
    template_xlsx,
    export_watchlist_xlsx,
)
from core.ai_summary import summarize_article
from core.llm import provider_status
from core.digest import DigestError, preview_digest, generate_digest, enrich_digest
from core.database import get_digest, list_digests
from core.pdf_export import digest_pdf
from core.config import ALLOW_WATCHLIST_UPLOAD
from core.auth import BasicAuthMiddleware
from core.playbooks import get_all_playbooks, get_playbook, generate_playbook_report
from core.url_tracer import trace_url_redirects
from core.deobfuscator import deobfuscate_payload
from core.hunting import generate_single_ioc_hunt_queries
from core.containment import generate_containment_scripts
from core.mitre import get_mitre_matrix_data, analyze_mitre_coverage, export_mitre_navigator_layer
from core.soc_analyst import (
    lookup_windows_event,
    analyze_command_line,
    calculate_impossible_travel,
    check_false_positive_indicators,
    classify_ip_infrastructure,
    dissect_user_agent,
)


app = FastAPI(title="LazySOC Threat Triage & Investigation Platform", version="3.0.0")


app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Added last so it runs first: no route is reachable without the login when auth is enabled.
app.add_middleware(BasicAuthMiddleware)

km = KeyManager()
engine = EnrichmentEngine(km)
vt_client = VirusTotalClient(km)
abuse_client = AbuseIPDBClient(km)
mail_checker = MailHealthChecker()
email_analyzer = EmailAnalyzer()

WEB_DIR = BASE_DIR / "web"
WEB_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25 MB max upload limit


# Models
class ScanRequest(BaseModel):
    raw_text: str
    providers: Optional[List[str]] = None
    use_cache: bool = True
    ttl_hours: int = CACHE_TTL_HOURS
    skip_private_ips: bool = True
    auto_throttle: bool = True
    airgapped_mode: bool = False


class KeyRequest(BaseModel):
    service: str
    key: str


class ExportRequest(BaseModel):
    results: List[Dict[str, Any]]
    format: str = "csv"  # 'csv' or 'json'
    defang: bool = True


class PlaybookReportRequest(BaseModel):
    playbook_id: str
    completed_task_ids: List[str]
    analyst_name: Optional[str] = "SOC Analyst"
    incident_id: Optional[str] = "INC-SOC-001"
    notes: Optional[str] = ""
    iocs: Optional[List[str]] = None


class TraceUrlRequest(BaseModel):
    url: str
    max_hops: Optional[int] = 8


class DeobfuscateRequest(BaseModel):
    payload: str


class HuntRequest(BaseModel):
    ioc: str
    type: str
    verdict: Optional[str] = "Malicious"


class MitreCoverageRequest(BaseModel):
    iocs: Optional[List[Dict[str, Any]]] = None
    playbook_id: Optional[str] = None


class SanitizeRequest(BaseModel):
    text: str
    mode: str = "defang"  # "defang" or "refang"


class EventLookupRequest(BaseModel):
    query: str


class LolbasRequest(BaseModel):
    command: str


class ImpossibleTravelRequest(BaseModel):
    lat1: float
    lon1: float
    time1: str
    lat2: float
    lon2: float
    time2: str
    loc1_name: Optional[str] = "Location A"
    loc2_name: Optional[str] = "Location B"


class FalsePositiveRequest(BaseModel):
    indicator: str
    type: Optional[str] = ""


class IpClassifyRequest(BaseModel):
    ip: str
    asn: Optional[str] = ""
    org: Optional[str] = ""


class UserAgentRequest(BaseModel):
    user_agent: str


class ContainmentRequest(BaseModel):
    iocs: List[Dict[str, Any]]
    rule_name: Optional[str] = "LAZYSOC_BLOCK"
    zone: Optional[str] = "untrust"


class MitreExportRequest(BaseModel):
    iocs: Optional[List[Dict[str, Any]]] = None
    playbook_id: Optional[str] = None
    layer_name: Optional[str] = "LazySOC Incident TTP Heatmap"


class GreyNoiseRequest(BaseModel):
    ip: str


class ThreatFoxRequest(BaseModel):
    ioc: str


class MalwareBazaarRequest(BaseModel):
    hash: str


class FeedSummaryRequest(BaseModel):
    link: str
    force: bool = False
    provider: Optional[str] = None


class DigestRequest(BaseModel):
    days: Optional[int] = 1
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    owner: Optional[str] = None
    mode: str = "critical"
    provider: Optional[str] = None
    query: Optional[str] = ""

XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
MAX_WATCHLIST_UPLOAD = 5 * 1024 * 1024




@app.get("/healthz")
def healthz():
    """Liveness probe for Docker / Render. Public even when login is enabled, so it returns nothing else."""
    return {"status": "ok"}


@app.get("/api/status")
def get_system_status():
    """Returns key pool stats and cache stats."""
    return {
        "pools": km.get_pool_counts(),
        "cache": get_cache_stats(),
        "services": {
            SERVICE_VT: km.get_service_summary(SERVICE_VT),
            SERVICE_ABUSE: km.get_service_summary(SERVICE_ABUSE),
        },
    }


@app.post("/api/parse")
def parse_indicators(req: Dict[str, str]):
    """Parses raw text and returns classified IoCs."""
    raw = req.get("raw_text", "")
    items = parse_raw_text(raw)
    return {
        "total": len(items),
        "items": [item.to_dict() for item in items],
    }


@app.get("/api/mail-health")
def check_mail_health(domain: str):
    """Audits MX, SPF, DMARC, and email spoofing posture for a domain."""
    clean_domain = domain.strip().lower()
    if not clean_domain:
        raise HTTPException(status_code=400, detail="Domain cannot be empty.")
    return mail_checker.check_domain(clean_domain)


@app.post("/api/scan")
def run_scan(req: ScanRequest):
    """Executes full scan on provided raw text."""
    items = parse_raw_text(req.raw_text)
    if not items:
        return {"total": 0, "results": [], "summary": {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}}

    results = []
    final_summary = None

    for event in engine.scan_items(
        items=items,
        providers=req.providers,
        use_cache=req.use_cache,
        ttl_hours=req.ttl_hours,
        skip_private_ips=req.skip_private_ips,
        auto_throttle=req.auto_throttle,
        airgapped_mode=req.airgapped_mode,
    ):
        if event["type"] == "item_result":
            results.append(event["data"])
        elif event["type"] == "complete":
            final_summary = event["summary"]

    return {
        "total": len(results),
        "results": results,
        "summary": final_summary or {
            "total": len(results),
            "malicious": sum(1 for r in results if r["verdict"] == VERDICT_MALICIOUS),
            "suspicious": sum(1 for r in results if r["verdict"] == VERDICT_SUSPICIOUS),
            "clean": sum(1 for r in results if r["verdict"] == VERDICT_CLEAN),
            "unknown": sum(1 for r in results if r["verdict"] == VERDICT_UNKNOWN),
        },
    }


@app.post("/api/scan/stream")
def run_scan_stream(req: ScanRequest):
    """Streams scan progress and item results using Server-Sent Events (SSE)."""
    items = parse_raw_text(req.raw_text)

    def event_stream():
        if not items:
            yield f"data: {json.dumps({'type': 'complete', 'summary': {'total': 0, 'malicious': 0, 'suspicious': 0, 'clean': 0, 'unknown': 0}})}\n\n"
            return

        for event in engine.scan_items(
            items=items,
            providers=req.providers,
            use_cache=req.use_cache,
            ttl_hours=req.ttl_hours,
            skip_private_ips=req.skip_private_ips,
            auto_throttle=req.auto_throttle,
            airgapped_mode=req.airgapped_mode,
        ):
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/recon")
def network_recon_endpoint(target: str):
    """Network recon for IP or domain: WHOIS/RDAP, Reverse DNS (PTR), Geolocation, ASN & Shodan."""
    tgt = target.strip()
    if not tgt:
        raise HTTPException(status_code=400, detail="Target cannot be empty.")
    return perform_recon(tgt)


@app.post("/api/analyze-eml")
async def analyze_eml_endpoint(file: Optional[UploadFile] = File(None), raw_text: Optional[str] = Form(None)):
    """Analyzes .eml file or raw email header text for phishing and spoofing indicators."""
    if file:
        content = await file.read(MAX_UPLOAD_SIZE + 1)
        if len(content) > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed upload size ({MAX_UPLOAD_SIZE // (1024*1024)} MB).")
        return email_analyzer.analyze(content, filename=file.filename or "email.eml")
    elif raw_text:
        if len(raw_text) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Pasted raw headers exceed 10 MB limit.")
        return email_analyzer.analyze(raw_text.encode("utf-8", errors="ignore"), filename="pasted_headers.eml")
    else:
        raise HTTPException(status_code=400, detail="Provide either a file or raw_text.")


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Parses uploaded CSV or TXT file."""
    content = await file.read(MAX_UPLOAD_SIZE + 1)
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum allowed upload size ({MAX_UPLOAD_SIZE // (1024*1024)} MB).")
    items = parse_uploaded_file(content, file.filename)
    return {
        "filename": file.filename,
        "total": len(items),
        "items": [item.to_dict() for item in items],
    }



ALLOW_KEY_MANAGEMENT = os.environ.get("ALLOW_KEY_MANAGEMENT", "false").lower() in ("true", "1", "yes")


@app.post("/api/keys")
def add_api_key(req: KeyRequest):
    if not ALLOW_KEY_MANAGEMENT:
        raise HTTPException(
            status_code=403,
            detail="Key modification via Web API is locked. Manage keys securely via Environment Variables or server config."
        )
    ok, msg = km.add_key(req.service, req.key)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg}


@app.delete("/api/keys")
def remove_api_key(service: str, key: str):
    if not ALLOW_KEY_MANAGEMENT:
        raise HTTPException(
            status_code=403,
            detail="Key removal via Web API is locked. API keys are protected on the server."
        )
    ok = km.remove_key(service, key)
    return {"success": ok}


@app.post("/api/keys/test")
def test_api_key(req: KeyRequest):
    if req.service == SERVICE_VT:
        ok, msg = vt_client.test_key(req.key)
    elif req.service == SERVICE_ABUSE:
        ok, msg = abuse_client.test_key(req.key)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown service: {req.service}")
    return {"valid": ok, "message": msg}


@app.get("/api/cache")
def list_cache(limit: int = 200):
    return {
        "stats": get_cache_stats(),
        "entries": get_all_cached_iocs(limit=limit),
        "history": get_scan_history(limit=15),
    }


@app.delete("/api/cache")
def clear_all_cache():
    count = clear_cache()
    return {"deleted": count}


@app.post("/api/export")
def export_results(req: ExportRequest):
    if req.format.lower() == "json":
        data = export_to_json(req.results, defang_output=req.defang)
        return StreamingResponse(
            iter([data]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=lazysoc_report.json"},
        )
    else:
        data = export_to_csv(req.results, defang_output=req.defang)
        return StreamingResponse(
            iter([data]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=lazysoc_report.csv"},
        )


@app.get("/api/feed")
def get_cyber_feed_endpoint(source: str = "all", limit: int = 40, owner: Optional[str] = None, watchlist_only: bool = False):
    """Fetches real-time cyber security news & threat advisories, tagged with watchlist matches."""
    return get_cyber_news(source=source, limit=max(1, min(limit, 200)), owner=owner, watchlist_only=watchlist_only)


@app.post("/api/feed/summarize")
def summarize_feed_article_endpoint(req: FeedSummaryRequest):
    """Summarizes one feed article with Claude. Only the public article text is sent to the API."""
    article = get_article_by_link(req.link)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found in the current feed.")
    return summarize_article(article, force=req.force, provider=req.provider)


@app.get("/api/ai/providers")
def get_ai_providers_endpoint():
    """Lists the AI providers (Claude API, local OpenAI-compatible LLM) and whether they are configured."""
    return provider_status()


@app.get("/api/digest/preview")
def preview_digest_endpoint(days: Optional[int] = 1, start_date: Optional[str] = None, end_date: Optional[str] = None,
                            owner: Optional[str] = None, mode: str = "critical", q: str = ""):
    """Lists the stored articles a digest for this period and filter would cover (no AI call)."""
    try:
        return preview_digest(days=days, start_date=start_date, end_date=end_date, owner=owner or None, mode=mode, query=q)
    except DigestError as e:
        raise HTTPException(status_code=400, detail=e.message)


@app.post("/api/digest")
def generate_digest_endpoint(req: DigestRequest):
    """Summarizes the period's (critical tools or general) news into one stored digest."""
    try:
        return generate_digest(days=req.days, start_date=req.start_date, end_date=req.end_date, owner=req.owner or None,
                               mode=req.mode, provider=req.provider, query=req.query or "")
    except DigestError as e:
        status = 404 if e.error_type == "NO_ARTICLES" else 400 if e.error_type in ("BAD_PERIOD", "BAD_MODE", "BAD_PROVIDER") else 502
        raise HTTPException(status_code=status, detail=e.message)


@app.get("/api/digests")
def list_digests_endpoint(limit: int = 20):
    return {"digests": list_digests(limit=max(1, min(limit, 100)))}


@app.get("/api/digest/{digest_id}")
def get_digest_endpoint(digest_id: int):
    digest = get_digest(digest_id)
    if not digest:
        raise HTTPException(status_code=404, detail="Digest not found.")
    return digest if "issues" in digest else enrich_digest(digest)


@app.get("/api/digest/{digest_id}/pdf")
def export_digest_pdf_endpoint(digest_id: int):
    """Exports a stored digest as PDF."""
    digest = get_digest(digest_id)
    if not digest:
        raise HTTPException(status_code=404, detail="Digest not found.")
    filename = f"lazysoc_digest_{digest['period_start']}_{digest['period_end']}.pdf"
    return StreamingResponse(
        iter([digest_pdf(digest)]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.get("/api/watchlist")
def get_watchlist_endpoint():
    """Returns the critical tools watchlist (owners, products, deployments)."""
    return get_watchlist_summary()


@app.post("/api/watchlist/upload")
async def upload_watchlist_endpoint(file: UploadFile = File(...), apply: bool = Form(False)):
    """Parses an uploaded critical tools list (.xlsx/.csv/.json). apply=false previews, apply=true replaces the watchlist."""
    if not ALLOW_WATCHLIST_UPLOAD:
        raise HTTPException(status_code=403, detail="Upload watchlist dinonaktifkan (ALLOW_WATCHLIST_UPLOAD=false).")
    content = await file.read(MAX_WATCHLIST_UPLOAD + 1)
    if len(content) > MAX_WATCHLIST_UPLOAD:
        raise HTTPException(status_code=413, detail="File watchlist maksimal 5 MB.")
    try:
        watchlist, report = import_watchlist(file.filename or "", content)
    except WatchlistImportError as e:
        raise HTTPException(status_code=400, detail=str(e))

    backup = save_watchlist(watchlist) if apply else None
    return {"applied": apply, "backup": backup, "report": report}


@app.get("/api/watchlist/template")
def download_watchlist_template_endpoint():
    return StreamingResponse(
        iter([template_xlsx()]),
        media_type=XLSX_MEDIA_TYPE,
        headers={"Content-Disposition": "attachment; filename=lazysoc_watchlist_template.xlsx"},
    )


@app.get("/api/watchlist/export")
def export_watchlist_endpoint():
    """Downloads the current watchlist as an editable .xlsx (same columns as the template)."""
    return StreamingResponse(
        iter([export_watchlist_xlsx(read_current_watchlist().get("assets", []))]),
        media_type=XLSX_MEDIA_TYPE,
        headers={"Content-Disposition": "attachment; filename=lazysoc_watchlist.xlsx"},
    )


@app.get("/api/watchlist/exposure")
def get_watchlist_exposure_endpoint(owner: Optional[str] = None, since_days: int = 365):
    """Lists CISA KEV entries that hit watchlist products, with per-deployment version status."""
    return get_kev_exposure(owner=owner, since_days=max(0, min(since_days, 3650)))


@app.get("/api/watchlist/cve/{cve_id}")
def check_watchlist_cve_endpoint(cve_id: str, owner: Optional[str] = None, assets: Optional[str] = None):
    """Checks one CVE's NVD version ranges against watchlist deployments."""
    extra = [a.strip() for a in (assets or "").split(",") if a.strip()]
    result = check_cve_impact(cve_id, owner=owner, extra_asset_ids=extra)
    if result.get("error_type") == "INVALID_ID":
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/api/cve")
def get_cve_endpoint(query: Optional[str] = None, limit: int = 30, page: int = 1):
    """Searches NIST NVD and vulnerability databases for CVE details with latest-first pagination."""
    return query_cve(search=query, limit=limit, page=page)


@app.get("/api/playbooks")
def list_playbooks_endpoint():
    """Returns all standardized SOC incident response playbooks and metadata."""
    return {"playbooks": get_all_playbooks()}


@app.get("/api/playbooks/{playbook_id}")
def get_playbook_endpoint(playbook_id: str):
    """Retrieves a detailed playbook with checklist tasks and remediation commands."""
    pb = get_playbook(playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail=f"Playbook '{playbook_id}' not found.")
    return pb


@app.post("/api/playbooks/report")
def generate_playbook_report_endpoint(req: PlaybookReportRequest):
    """Generates an audit report for playbook execution ready for ticket handover."""
    report = generate_playbook_report(
        playbook_id=req.playbook_id,
        completed_task_ids=req.completed_task_ids,
        analyst_name=req.analyst_name,
        incident_id=req.incident_id,
        notes=req.notes,
        iocs=req.iocs,
    )
    if "error" in report:
        raise HTTPException(status_code=400, detail=report["error"])
    return report


@app.post("/api/trace-url")
def trace_url_endpoint(req: TraceUrlRequest):
    """Traces URL redirect chain safely and passively, evaluating domain age and SSL certificates."""
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")
    return trace_url_redirects(url, max_hops=req.max_hops or 8)


@app.post("/api/deobfuscate")
def deobfuscate_endpoint(req: DeobfuscateRequest):
    """De-obfuscates PowerShell commands, base64, hex, and percent-encoded payloads."""
    payload = req.payload.strip()
    if not payload:
        raise HTTPException(status_code=400, detail="Payload cannot be empty.")
    return deobfuscate_payload(payload)


@app.post("/api/hunt")
def hunt_single_ioc_endpoint(req: HuntRequest):
    """Generates targeted multi-SIEM threat hunting queries for a specific single IoC."""
    ioc_val = req.ioc.strip()
    if not ioc_val:
        raise HTTPException(status_code=400, detail="IoC cannot be empty.")
    return generate_single_ioc_hunt_queries(ioc_val, req.type, req.verdict)


@app.get("/api/mitre")
def get_mitre_matrix_endpoint():
    """Returns complete MITRE ATT&CK Matrix tactical columns and technique definitions."""
    return get_mitre_matrix_data()


@app.post("/api/mitre/coverage")
def analyze_mitre_coverage_endpoint(req: MitreCoverageRequest):
    """Analyzes and correlates current triage IoCs and playbook to generate an active TTP heatmap."""
    return analyze_mitre_coverage(req.iocs or [], req.playbook_id)


@app.post("/api/sanitize")
def sanitize_text_endpoint(req: SanitizeRequest):
    """Defangs or refangs free-form text, indicators, and URLs safely."""
    raw_text = req.text
    if req.mode == "refang":
        # Turn defanged text back to live indicators
        from core.parser import refang_text
        cleaned = refang_text(raw_text)
        return {"result": cleaned, "mode": "refang"}
    else:
        # Aggressive defanging for safe pasting
        from core.parser import parse_raw_text, defang_text
        items = parse_raw_text(raw_text)
        replaced = raw_text
        for item in items:
            defanged_val = defang_text(item.value, item.ioc_type)
            if item.value in replaced:
                replaced = replaced.replace(item.value, defanged_val)
            elif item.raw in replaced:
                replaced = replaced.replace(item.raw, defanged_val)
        
        # Also clean up any lingering http:// or https://
        replaced = replaced.replace("https://", "hxxps://").replace("http://", "hxxp://")
        return {"result": replaced, "mode": "defang", "indicators_found": len(items)}


# ==============================================================================
# L1 SOC ANALYST TOOLKIT ENDPOINTS
# ==============================================================================

@app.post("/api/soc/event-lookup")
def soc_event_lookup_endpoint(req: EventLookupRequest):
    """Decodes Windows Event IDs, NTSTATUS error codes, and Logon Types."""
    return lookup_windows_event(req.query)


@app.post("/api/soc/lolbas")
def soc_lolbas_endpoint(req: LolbasRequest):
    """Analyzes command line for LOLBAS binaries and suspicious attack arguments."""
    return analyze_command_line(req.command)


@app.post("/api/soc/impossible-travel")
def soc_impossible_travel_endpoint(req: ImpossibleTravelRequest):
    """Calculates distance, elapsed time, and required speed between two login events."""
    return calculate_impossible_travel(
        lat1=req.lat1,
        lon1=req.lon1,
        time1_str=req.time1,
        lat2=req.lat2,
        lon2=req.lon2,
        time2_str=req.time2,
        loc1_name=req.loc1_name or "Location A",
        loc2_name=req.loc2_name or "Location B",
    )


@app.post("/api/soc/fp-check")
def soc_fp_check_endpoint(req: FalsePositiveRequest):
    """Validates indicators against legitimate enterprise CDNs, RMM tools, and NSRL hashes."""
    return check_false_positive_indicators(req.indicator, req.type or "")


@app.post("/api/soc/ip-classify")
def soc_ip_classify_endpoint(req: IpClassifyRequest):
    """Classifies IP address into Tor, Public Cloud Datacenter, VPN, or Residential."""
    return classify_ip_infrastructure(req.ip, asn_info=req.asn or "", org_info=req.org or "")


@app.post("/api/soc/user-agent")
def soc_user_agent_endpoint(req: UserAgentRequest):
    """Dissects HTTP User-Agent string for scanners, scripting libraries, and bots."""
    return dissect_user_agent(req.user_agent)


@app.post("/api/containment/generate")
def generate_containment_endpoint(req: ContainmentRequest):
    """Generates ready-to-run firewall blocklists and EDR host containment scripts."""
    return generate_containment_scripts(
        iocs=req.iocs,
        rule_name=req.rule_name or "LAZYSOC_BLOCK",
        zone=req.zone or "untrust",
    )


@app.post("/api/mitre/export-layer")
def export_mitre_layer_endpoint(req: MitreExportRequest):
    """Exports MITRE ATT&CK Navigator v4.5 Layer JSON ready to drag-and-drop into Navigator."""
    layer_data = export_mitre_navigator_layer(
        iocs=req.iocs or [],
        active_playbook_id=req.playbook_id,
        layer_name=req.layer_name or "LazySOC Incident TTP Heatmap",
    )
    json_bytes = json.dumps(layer_data, indent=2).encode("utf-8")
    return StreamingResponse(
        iter([json_bytes]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=lazysoc_mitre_layer.json"},
    )


@app.post("/api/soc/greynoise")
def soc_greynoise_endpoint(req: GreyNoiseRequest):
    """Checks GreyNoise Community API for internet scanners and RIOT benign services."""
    return engine.greynoise_client.check_ip(req.ip)


@app.post("/api/soc/threatfox")
def soc_threatfox_endpoint(req: ThreatFoxRequest):
    """Queries abuse.ch ThreatFox database for malware attribution and C2 context."""
    return engine.threatfox_client.search_ioc(req.ioc)


@app.post("/api/soc/malwarebazaar")
def soc_malwarebazaar_endpoint(req: MalwareBazaarRequest):
    """Queries abuse.ch MalwareBazaar for sample metadata, signatures, and tags."""
    return engine.malwarebazaar_client.check_hash(req.hash)


@app.get("/", response_class=HTMLResponse)


def serve_index():
    index_file = WEB_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse("<h1>LazySOC Web UI file missing</h1>", status_code=404)
    return HTMLResponse(index_file.read_text(encoding="utf-8"))


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    is_dev = os.environ.get("ENV", "development") == "development"
    uvicorn.run("server:app", host=host, port=port, reload=is_dev)
