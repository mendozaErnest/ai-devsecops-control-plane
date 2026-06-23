// ── dashboard.js — findings, projects, AI status, scan, report, PDF ──────────
import {
  t, applyI18n, currentLang, showFeedback, ensureServerContext,
  escapeHtml, setText, setWidth,
  severityKey, severityClass, sevStyle,
  fileLine, formatRelativeTime,
  techStyle, lifecycleStyle,
  shortPath, cleanCodeFences, formatApiError,
  detectTool, buildToolBadge,
  IC_SPARKLE, IC_WARN, IC_CROSS, IC_CLOCK,
} from "/static/js/utils.js";
import {
  getProjects, getProjectFindings, scanProject, getAiStatus, generateRemediation, getReport,
  runAgenticDastScan, getAgenticDastStatus,
  getProfiles, trainRiskModel,
} from "/static/js/api.js";
import {
  showRemediationModal, openReasonModal, openAuditModal, postLifecycle,
  showProjectModal,
} from "/static/js/modal.js";

// ── DOM refs ──────────────────────────────────────────────────────────────────
const scannerFilterEl     = document.getElementById("scanner-filter-icons");
const panelRunScanButton  = document.getElementById("panel-run-scan");
const scanStackIcons      = document.getElementById("scan-stack-icons");
const topNav              = document.querySelector(".nav");
const refreshButton       = document.getElementById("refresh-findings");
const projectsList        = document.getElementById("projects-list");
const projectStatus       = document.getElementById("project-status");
const projectSelect       = document.getElementById("project-select");
const currentProjectTitle = document.getElementById("current-project-title");
const tableBody           = document.getElementById("findings-table-body");
const tableStatus         = document.getElementById("table-status");
const scanStatus          = document.getElementById("scan-status");
const highCount           = document.getElementById("high-count");
const mediumCount         = document.getElementById("medium-count");
const totalCount          = document.getElementById("total-count");
const criticalCount       = document.getElementById("critical-count");
const lowCount            = document.getElementById("low-count");
const moduleCount         = document.getElementById("module-count");
const criticalCopy        = document.getElementById("critical-copy");
const totalRadialCount    = document.getElementById("total-radial-count");
const filterAllCount      = document.getElementById("filter-all-count");
const filterCriticalCount = document.getElementById("filter-critical-count");
const filterHighCount     = document.getElementById("filter-high-count");
const filterBreachCount   = document.getElementById("filter-breach-count");
const aiStatusBadge       = document.getElementById("ai-status-badge");
const aiBadgeText         = document.getElementById("ai-badge-text");
const aiModelChip         = document.getElementById("ai-model-chip");
const scanAdapterStatus   = document.getElementById("scan-adapter-status");
const aiEngineSummary     = document.getElementById("ai-engine-summary");
const viewFindingsBtn     = document.getElementById("view-findings-btn");
const viewReportBtn       = document.getElementById("view-report-btn");
const findingsTableView   = document.getElementById("findings-table-view");
const findingsReportView  = document.getElementById("findings-report-view");
const reportLoading       = document.getElementById("report-loading");
const reportContent       = document.getElementById("report-content");
const exportPdfBtn        = document.getElementById("export-pdf-btn");
const repoDiv             = document.querySelector(".repo");
const projectsPopover     = document.getElementById("projects-popover");

// ── App state ─────────────────────────────────────────────────────────────────
export let selectedProject = null;
export let projects = [];
export let aiStatus = { available: false, reason: "Checking AI engine" };
export let currentFindings = [];
let scanProfiles = [];
let scanProfilesLoaded = false;

let activeFilter = "all";
let activeScannerFilter = "all";
let sortByRisk = false;
let currentPage  = 1;
const PAGE_SIZE  = 20;
let filteredFindings = [];
let activeView = "findings";
let chartSeverity = null, chartStatus = null, chartRules = null;

const TOOL_CHIP_META = {
  semgrep:     { label: "Semgrep",    short: "Se"  },
  bandit:      { label: "Bandit",     short: "Ba"  },
  sonarqube:   { label: "SonarQube",  short: "SQ"  },
  eslint:      { label: "ESLint",     short: "ES"  },
  pylint:      { label: "Pylint",     short: "PyL" },
  zap:         { label: "OWASP ZAP",  short: "ZAP" },
  "pip-audit": { label: "pip-audit",  short: "pip" },
  odc:         { label: "ODC",        short: "DC"  },
  checkov:     { label: "Checkov",    short: "Ck"  },
  trivy:       { label: "Trivy",      short: "Tv"  },
  gitleaks:    { label: "Gitleaks",   short: "GL"  },
  unknown:     { label: "Scanner",    short: "?"   },
};

// ── Floating nav ──────────────────────────────────────────────────────────────
export function updateFloatingNav() {
  if (!topNav) return;
  const floating = window.scrollY > 18;
  topNav.classList.toggle("is-floating", floating);
  topNav.closest(".app")?.classList.toggle("nav-floating", floating);
}

// ── AI status badge ───────────────────────────────────────────────────────────
export function renderAiStatusBadge() {
  if (!aiStatusBadge) return;
  const dot = aiStatusBadge.querySelector(".dot");
  const model = aiStatus.model || "local model";
  if (aiStatus.available) {
    if (dot) dot.style.background = "var(--mint)";
    aiStatusBadge.style.background = "var(--mint-soft)";
    aiStatusBadge.style.borderColor = "rgba(158,255,224,0.18)";
    aiStatusBadge.style.color = "var(--mint)";
    if (aiBadgeText) aiBadgeText.textContent = "";
    if (scanAdapterStatus) scanAdapterStatus.textContent = t("scanning-adapters");
    if (aiEngineSummary) aiEngineSummary.textContent = t("local-model-ready");
    if (aiModelChip) aiModelChip.textContent = `Live · ${model}`;
  } else {
    if (dot) dot.style.background = "var(--t-mute)";
    aiStatusBadge.style.background = "var(--surface-2)";
    aiStatusBadge.style.borderColor = "var(--border)";
    aiStatusBadge.style.color = "var(--t-dim)";
    if (aiBadgeText) aiBadgeText.textContent = "";
    if (scanAdapterStatus) scanAdapterStatus.textContent = t("ai-adapter-offline");
    if (aiEngineSummary) aiEngineSummary.textContent = t("ollama-offline");
    if (aiModelChip) aiModelChip.textContent = `Offline · Ollama`;
  }
}

// ── Counters + radial ─────────────────────────────────────────────────────────
function updateCounters(records) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  records.forEach((r) => { counts[severityKey(r.severity)] += 1; });
  const total = records.length;
  const files = new Set(records.map((r) => shortPath(r.file_path || "")).filter(Boolean));
  const { breached, warning } = _countSlaStatuses(records);

  if (criticalCount) criticalCount.textContent = counts.critical;
  if (highCount) highCount.textContent = counts.high;
  if (mediumCount) mediumCount.textContent = counts.medium;
  if (lowCount) lowCount.textContent = counts.low;
  if (totalCount) totalCount.textContent = total;
  if (totalRadialCount) totalRadialCount.textContent = total;

  const modWord  = currentLang === "es" ? "módulos" : "modules";
  const critWord = currentLang === "es" ? "críticos" : "critical";
  if (moduleCount) moduleCount.textContent = `${files.size || (selectedProject ? 1 : 0)} ${modWord}`;
  if (criticalCopy) criticalCopy.textContent = `${counts.critical} ${critWord}`;
  if (filterAllCount) filterAllCount.textContent = total;
  if (filterCriticalCount) filterCriticalCount.textContent = counts.critical;
  if (filterHighCount) filterHighCount.textContent = counts.high;
  if (filterBreachCount) filterBreachCount.textContent = breached;
  setText("sla-breaches", breached);
  setText("sla-foot", _buildSlaFoot(breached, warning));

  setWidth("sev-bar-critical", _pct(counts.critical, total));
  setWidth("sev-bar-high",     _pct(counts.high,     total));
  setWidth("sev-bar-medium",   _pct(counts.medium,   total));
  setWidth("sev-bar-low",      _pct(counts.low,      total));

  _updateRadialArcs(counts, total);
}

// ── SLA helpers ───────────────────────────────────────────────────────────────
function effectiveSlaStatus(record) {
  if (record.sla_status) return record.sla_status;
  if (!record.sla_deadline) return "unknown";
  return new Date(record.sla_deadline) < new Date() ? "breached" : "ok";
}

function _buildSlaFoot(breached, warning) {
  const overdueWord = currentLang === "es" ? "vencidos" : "overdue";
  const warningWord = currentLang === "es" ? "por vencer" : "due soon";
  const parts = [];
  if (breached > 0) parts.push(`🔴 ${breached} ${overdueWord}`);
  if (warning > 0)  parts.push(`⚠ ${warning} ${warningWord}`);
  return parts.length > 0 ? parts.join("   ") : `0 ${overdueWord} · CVSS ≥ 9.0`;
}

function _pct(n, total) { return total ? (n / total) * 100 : 0; }

function _countSlaStatuses(records) {
  let breached = 0, warning = 0;
  for (const r of records) {
    const s = effectiveSlaStatus(r);
    if (s === "breached") breached++;
    else if (s === "warning") warning++;
  }
  return { breached, warning };
}

function _updateRadialArcs(counts, total) {
  const circumference = 540;
  let offset = 0;
  [
    ["radial-critical", counts.critical],
    ["radial-high",     counts.high],
    ["radial-medium",   counts.medium],
    ["radial-low",      counts.low],
  ].forEach(([id, count]) => {
    const circle = document.getElementById(id);
    if (!circle) return;
    const length = total ? (count / total) * circumference : 0;
    circle.setAttribute("stroke-dasharray", `${length} ${circumference}`);
    circle.setAttribute("stroke-dashoffset", String(-offset));
    offset += length;
  });
}

// ── Table rendering ───────────────────────────────────────────────────────────
function renderMessage(message) {
  tableBody.innerHTML = "";
  const cell = document.createElement("div");
  cell.style.cssText = "padding:60px 20px;text-align:center;color:var(--t-dim);";
  cell.innerHTML = `
    <svg style="margin:0 auto 16px;display:block;opacity:.25;" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
      <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"/>
    </svg>
    <p style="font-size:.9rem;color:var(--t-dim);">${escapeHtml(message)}</p>
  `;
  tableBody.appendChild(cell);
}

function buildLifecycleBadge(record) {
  const wrap = document.createElement("span");
  wrap.style.cssText = "display:inline-flex;align-items:center;gap:5px;flex-wrap:wrap;";

  const badge = document.createElement("span");
  const isRegression = String(record.status).toLowerCase() === "regression";
  badge.style.cssText =
    `display:inline-flex;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600;` +
    lifecycleStyle(record.status);
  badge.textContent = (record.status || "open").replace("_", " ");
  if (isRegression) badge.classList.add("badge-regression");
  wrap.appendChild(badge);

  if (record.regression_count > 0) {
    const rc = document.createElement("span");
    rc.style.cssText =
      "padding:1px 6px;border-radius:4px;font-size:.7rem;font-weight:700;" +
      "background:rgba(248,81,73,.15);color:#ff7b72;border:1px solid rgba(248,81,73,.3);";
    rc.title = `Reapareció ${record.regression_count} vez/veces`;
    rc.textContent = `↩${record.regression_count}`;
    wrap.appendChild(rc);
  }

  if (record.has_remediation) {
    const rem = document.createElement("span");
    rem.style.cssText =
      "padding:1px 6px;border-radius:4px;font-size:.7rem;font-weight:600;" +
      "background:rgba(47,129,247,.15);color:#6cb6ff;border:1px solid rgba(47,129,247,.3);";
    rem.textContent = "fix";
    wrap.appendChild(rem);
  }

  return wrap;
}

function buildSlaBadge(record) {
  // Prefer server-computed sla_status; fall back to local computation from deadline.
  let status = record.sla_status;
  if (!status && record.sla_deadline) {
    const remaining = new Date(record.sla_deadline) - Date.now();
    if (["accepted_risk", "false_positive", "fixed"].includes(record.status)) {
      status = "exempt";
    } else if (remaining < 0) {
      status = "breached";
    } else if (remaining <= 3 * 86400000) {
      status = "warning";
    } else {
      status = "ok";
    }
  }

  // Exempt or no deadline → no badge shown
  if (!record.sla_deadline || status === "exempt") return document.createElement("span");

  const deadline = new Date(record.sla_deadline);
  const label = deadline.toLocaleDateString("es-MX", { month: "short", day: "numeric" });

  const clsMap = { ok: "sla ok", warning: "sla warn", breached: "sla brk", unknown: "sla ok" };
  const iconMap = { ok: "✓", warning: "⚠", breached: "!", unknown: "?" };

  const span = document.createElement("span");
  span.className = clsMap[status] || "sla ok";
  span.textContent = `${iconMap[status] || "?"} ${label}`;
  span.title = `SLA deadline: ${deadline.toLocaleDateString("es-MX")} (${status})`;
  return span;
}

function buildRiskBadge(record) {
  const score = record.risk_score;
  if (score == null) return document.createElement("span");

  const pct = Math.round(score * 100);
  let color;
  if (pct >= 70) color = "#ef4444";
  else if (pct >= 40) color = "#d29922";
  else color = "#3b82f6";

  const wrap = document.createElement("span");
  wrap.style.cssText = "display:inline-flex;flex-direction:column;gap:2px;min-width:52px;";
  wrap.title = `${t("lbl-risk-score")}: ${pct}%`;

  const label = document.createElement("span");
  label.style.cssText = `font-size:.62rem;font-weight:700;color:${color};line-height:1;`;
  label.textContent = `${pct}%`;

  const track = document.createElement("span");
  track.style.cssText =
    "display:block;height:3px;border-radius:2px;background:var(--surface-3,#21262d);overflow:hidden;";
  const fill = document.createElement("span");
  fill.style.cssText =
    `display:block;height:100%;width:${pct}%;background:${color};border-radius:2px;`;
  track.appendChild(fill);

  wrap.append(label, track);
  return wrap;
}

function buildActionButtons(record) {
  const wrap = document.createElement("span");
  wrap.style.cssText = "display:inline-flex;align-items:center;gap:6px;flex-wrap:nowrap;";

  const btnBase =
    "display:inline-flex;align-items:center;gap:5px;border:1px solid var(--border-2);" +
    "cursor:pointer;border-radius:8px;padding:5px 9px;font-size:11.5px;font-weight:500;" +
    "transition:background .12s,color .12s,border-color .12s;background:var(--surface-2);";
  const isIgnored = record.status === "accepted_risk" || record.status === "false_positive";

  const fixBtn = document.createElement("button");
  fixBtn.type = "button";
  fixBtn.title = aiStatus.available ? "Generar Parche" : "Ollama no disponible";
  fixBtn.style.cssText = btnBase + (aiStatus.available
    ? "color:#D9E2EE;border-color:rgba(122,140,165,.32);"
    : "color:var(--t-mute);cursor:not-allowed;opacity:.55;");
  fixBtn.innerHTML =
    `<span style="display:inline-flex;align-items:center;flex-shrink:0;">${IC_SPARKLE}</span>` +
    `<span>${t("btn-fix")}</span>`;
  fixBtn.disabled = !aiStatus.available;
  fixBtn.addEventListener("click", () => remediateFinding(record, fixBtn));
  wrap.appendChild(fixBtn);

  if (!isIgnored) {
    const arBtn = document.createElement("button");
    arBtn.type = "button";
    arBtn.title = currentLang === "es" ? "Riesgo aceptado" : "Accept risk";
    arBtn.style.cssText = btnBase + "color:var(--high);border-color:rgba(239,68,68,.24);";
    arBtn.innerHTML = `${IC_WARN} ${t("btn-risk")}`;
    arBtn.addEventListener("click", () => openReasonModal(
      currentLang === "es" ? "Aceptar riesgo" : "Accept risk",
      currentLang === "es"
        ? `Justifica el riesgo aceptado para el finding ${String(record.id).slice(0, 8)}`
        : `Justify accepted risk for finding ${String(record.id).slice(0, 8)}`,
      (reason) => postLifecycle(record.id, "accept-risk", reason, () => loadFindings())
    ));
    wrap.appendChild(arBtn);

    const fpBtn = document.createElement("button");
    fpBtn.type = "button";
    fpBtn.title = currentLang === "es" ? "Falso positivo" : "False positive";
    fpBtn.style.cssText = btnBase + "color:var(--t-dim);";
    fpBtn.innerHTML = `${IC_CROSS} ${t("btn-fp")}`;
    fpBtn.addEventListener("click", () => openReasonModal(
      currentLang === "es" ? "Falso positivo" : "False positive",
      currentLang === "es"
        ? `Justifica por qué el finding ${String(record.id).slice(0, 8)} es un falso positivo`
        : `Justify why finding ${String(record.id).slice(0, 8)} is a false positive`,
      (reason) => postLifecycle(record.id, "false-positive", reason, () => loadFindings())
    ));
    wrap.appendChild(fpBtn);
  }

  const auditBtn = document.createElement("button");
  auditBtn.type = "button";
  auditBtn.title = currentLang === "es" ? "Ver historial" : "View history";
  auditBtn.style.cssText = btnBase + "color:var(--t-dim);";
  auditBtn.innerHTML = `${IC_CLOCK} ${t("btn-history")}`;
  auditBtn.addEventListener("click", () => openAuditModal(record));
  wrap.appendChild(auditBtn);

  return wrap;
}

function getFilteredSorted(records, filter) {
  let result = [...records];
  if (activeScannerFilter !== "all") result = result.filter((r) => detectTool(r) === activeScannerFilter);
  if (filter === "critical") result = result.filter((r) => String(r.severity || "").toUpperCase() === "CRITICAL");
  else if (filter === "high") result = result.filter((r) => String(r.severity || "").toUpperCase() === "HIGH");
  else if (filter === "breach") result = result.filter((r) => r.sla_deadline && new Date(r.sla_deadline) < new Date());
  if (sortByRisk) {
    result.sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0));
  } else {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    result.sort((a, b) =>
      (order[String(a.severity || "").toUpperCase()] ?? 4) -
      (order[String(b.severity || "").toUpperCase()] ?? 4)
    );
  }
  return result;
}

function renderScannerFilterIcons() {
  if (!scannerFilterEl) return;
  scannerFilterEl.innerHTML = "";

  const toolCounts = {};
  currentFindings.forEach((f) => {
    const tool = detectTool(f);
    toolCounts[tool] = (toolCounts[tool] || 0) + 1;
  });

  const tools = Object.keys(toolCounts);
  if (tools.length < 2) {
    scannerFilterEl.style.display = "none";
    return;
  }
  scannerFilterEl.style.display = "";

  const allChip = document.createElement("button");
  allChip.type = "button";
  allChip.className = `scan-chip all-scan${activeScannerFilter === "all" ? " on" : ""}`;
  allChip.title = "Todos los scanners";
  allChip.innerHTML = `<span>All</span><span class="sn">${currentFindings.length}</span>`;
  allChip.addEventListener("click", () => setActiveScannerFilter("all"));
  scannerFilterEl.appendChild(allChip);

  tools.forEach((tool) => {
    const meta = TOOL_CHIP_META[tool] || TOOL_CHIP_META.unknown;
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = `scan-chip ${tool}${activeScannerFilter === tool ? " on" : ""}`;
    chip.title = meta.label;
    chip.innerHTML = `<span>${escapeHtml(meta.short)}</span><span class="sn">${toolCounts[tool]}</span>`;
    chip.addEventListener("click", () => setActiveScannerFilter(tool));
    scannerFilterEl.appendChild(chip);
  });
}

function setActiveScannerFilter(key) {
  activeScannerFilter = key;
  currentPage = 1;
  filteredFindings = getFilteredSorted(currentFindings, activeFilter);
  renderPage();
  renderScannerFilterIcons();
}

function renderPage() {
  tableBody.innerHTML = "";
  const paginatorEl = document.getElementById("findings-paginator");
  const total = filteredFindings.length;
  const totalPages = Math.ceil(total / PAGE_SIZE);
  const start = (currentPage - 1) * PAGE_SIZE;
  const pageItems = filteredFindings.slice(start, start + PAGE_SIZE);

  if (total === 0) {
    renderMessage(t("no-findings"));
    if (paginatorEl) paginatorEl.innerHTML = "";
    return;
  }

  const SEV_LABEL = { c: "CRIT", h: "HIGH", m: "MED", l: "LOW" };
  const SEV_COLOR = {
    c: "background:rgba(239,68,68,.15);color:#ef4444;",
    h: "background:rgba(220,38,38,.12);color:#dc2626;",
    m: "background:rgba(210,153,34,.13);color:#d29922;",
    l: "background:rgba(59,130,246,.13);color:#3b82f6;",
  };

  pageItems.forEach((record) => {
    const row = document.createElement("div");
    row.className = "frow";

    const line = fileLine(record);
    const path = shortPath(record.file_path || "unknown");
    const rule = record.rule_id || String(record.id || "UNKNOWN").slice(0, 12);
    const meta = record.cve_id || record.cvss
      ? `CVSS ${record.cvss || ""}`.trim()
      : formatRelativeTime(record.created_at || record.discovered_at);
    const sc = severityClass(record.severity);

    const mark = document.createElement("div");
    mark.className = `sev-mark ${sc}`;

    const body = document.createElement("div");
    body.className = "body";
    const desc = record.description || "Security finding";
    const sevBadge =
      `<span style="display:inline-flex;padding:1px 6px;border-radius:4px;font-size:.66rem;font-weight:700;${SEV_COLOR[sc] || SEV_COLOR.l}">${SEV_LABEL[sc] || "LOW"}</span>`;
    body.innerHTML = `
      <div class="top-row">
        ${sevBadge}
        <span class="rule ttip" data-tip="${escapeHtml(desc)}" style="cursor:help;">${escapeHtml(desc)}</span>
        <span class="id">${escapeHtml(rule)}</span>
      </div>
      <div class="bot-row">
        <span class="path">${escapeHtml(path)}:<span class="ln">${escapeHtml(line)}</span></span>
        <span class="dot-sep">·</span>
        ${buildToolBadge(record)}
        <span class="dot-sep">·</span>
        <span class="tool">${escapeHtml(meta)}</span>
      </div>
    `;

    const sla    = buildSlaBadge(record);
    const risk   = buildRiskBadge(record);
    const action = buildActionButtons(record);

    row.append(mark, body, sla, risk, action);
    tableBody.appendChild(row);
  });

  if (paginatorEl) {
    if (totalPages <= 1) {
      paginatorEl.innerHTML = `<span>${total} hallazgos</span>`;
    } else {
      const btnStyle =
        "padding:3px 9px;border-radius:6px;border:1px solid var(--border-2);" +
        "background:var(--surface-2);color:var(--t-dim);font-size:11.5px;cursor:pointer;transition:background .12s;";
      const btnActiveStyle =
        "padding:3px 9px;border-radius:6px;border:1px solid var(--border-2);" +
        "background:var(--t-hi);color:var(--bg);font-size:11.5px;cursor:pointer;font-weight:700;";
      const from = start + 1, to = Math.min(start + PAGE_SIZE, total);
      paginatorEl.innerHTML = "";

      const info = document.createElement("span");
      info.textContent = `${from}–${to} de ${total}`;
      paginatorEl.appendChild(info);

      const pages = document.createElement("div");
      pages.style.cssText = "display:flex;align-items:center;gap:4px;";

      const prevBtn = document.createElement("button");
      prevBtn.type = "button"; prevBtn.textContent = "←"; prevBtn.style.cssText = btnStyle;
      prevBtn.disabled = currentPage === 1;
      if (currentPage === 1) prevBtn.style.opacity = ".35";
      prevBtn.addEventListener("click", () => { currentPage--; renderPage(); });
      pages.appendChild(prevBtn);

      const maxVisible = 7;
      let pStart = Math.max(1, currentPage - Math.floor(maxVisible / 2));
      let pEnd = Math.min(totalPages, pStart + maxVisible - 1);
      if (pEnd - pStart < maxVisible - 1) pStart = Math.max(1, pEnd - maxVisible + 1);

      for (let p = pStart; p <= pEnd; p++) {
        const pb = document.createElement("button");
        pb.type = "button"; pb.textContent = p;
        pb.style.cssText = p === currentPage ? btnActiveStyle : btnStyle;
        const pg = p;
        pb.addEventListener("click", () => { currentPage = pg; renderPage(); });
        pages.appendChild(pb);
      }

      const nextBtn = document.createElement("button");
      nextBtn.type = "button"; nextBtn.textContent = "→"; nextBtn.style.cssText = btnStyle;
      nextBtn.disabled = currentPage === totalPages;
      if (currentPage === totalPages) nextBtn.style.opacity = ".35";
      nextBtn.addEventListener("click", () => { currentPage++; renderPage(); });
      pages.appendChild(nextBtn);

      paginatorEl.appendChild(pages);
    }
  }
}

export function renderRows(records) {
  updateCounters(records);
  filteredFindings = getFilteredSorted(records, activeFilter);
  currentPage = 1;
  renderPage();
}

function setActiveChip(filter) {
  activeFilter = filter;
  currentPage = 1;
  ["chip-all", "chip-critical", "chip-high", "chip-breach"].forEach((id) => {
    document.getElementById(id)?.classList.remove("on");
  });
  const ids = { all: "chip-all", critical: "chip-critical", high: "chip-high", breach: "chip-breach" };
  document.getElementById(ids[filter])?.classList.add("on");
  filteredFindings = getFilteredSorted(currentFindings, activeFilter);
  renderPage();
}

// ── Scanner badge helper (CAMBIO 4b) ──────────────────────────────────────────
const TOOL_BADGE_COLOR = {
  semgrep:     "#2f81f7",
  bandit:      "#d29922",
  sonarqube:   "#4e9bf5",
  eslint:      "#a371f7",
  pylint:      "#3fb950",
  zap:         "#ff7b72",
  "pip-audit": "#58a6ff",
  odc:         "#e3693e",
  checkov:     "#7c5cbf",
  trivy:       "#1b9cf2",
  gitleaks:    "#e05c3a",
  unknown:     "#8b949e",
};

function buildScannerIconBadge(toolKey) {
  const meta  = TOOL_CHIP_META[toolKey] || TOOL_CHIP_META.unknown;
  const color = TOOL_BADGE_COLOR[toolKey] || TOOL_BADGE_COLOR.unknown;
  return `<span style="padding:1px 6px;border-radius:4px;font-size:.67rem;font-weight:700;font-family:var(--f-mono);background:${color}1a;color:${color};border:1px solid ${color}40;" title="${escapeHtml(meta.label)}">${escapeHtml(meta.short)}</span>`;
}

// ── Project rendering ─────────────────────────────────────────────────────────
export function renderProjects() {
  projectsList.innerHTML = "";
  projectStatus.textContent = `${projects.length} ${t("registered-projects")}`;
  setText("repo-branch-chip", selectedProject?.source_type === "repo" ? "main" : selectedProject?.technology || "main");
  if (projectSelect) projectSelect.innerHTML = "";

  if (projects.length === 0) {
    if (projectSelect) {
      const option = document.createElement("option");
      option.textContent = "no-project";
      projectSelect.appendChild(option);
    }
    const empty = document.createElement("p");
    empty.style.cssText = "padding:32px 20px;font-size:.83rem;color:var(--muted);text-align:center;";
    empty.textContent = "Aún no hay proyectos. Carga un ZIP o clona un repositorio.";
    projectsList.appendChild(empty);
    return;
  }

  projects.forEach((project) => {
    if (projectSelect) {
      const option = document.createElement("option");
      option.value = project.id;
      option.textContent = project.name;
      option.selected = Boolean(selectedProject && selectedProject.id === project.id);
      projectSelect.appendChild(option);
    }

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "proj-btn" + (selectedProject && selectedProject.id === project.id ? " active" : "");
    const createdAt = project.created_at ? new Date(project.created_at).toLocaleString() : "—";
    const critCount = project.critical_findings || 0;
    const totalF   = project.finding_count || 0;

    const summary = project.findings_summary || {};
    const sevParts = [];
    if ((summary.CRITICAL || 0) > 0) sevParts.push(`<span style="padding:1px 6px;border-radius:4px;font-size:.67rem;font-weight:700;background:rgba(248,81,73,.2);color:#f85149;" title="CRITICAL">C:${summary.CRITICAL}</span>`);
    if ((summary.HIGH     || 0) > 0) sevParts.push(`<span style="padding:1px 6px;border-radius:4px;font-size:.67rem;font-weight:700;background:rgba(227,105,62,.2);color:#e3693e;" title="HIGH">H:${summary.HIGH}</span>`);
    if ((summary.MEDIUM   || 0) > 0) sevParts.push(`<span style="padding:1px 6px;border-radius:4px;font-size:.67rem;font-weight:700;background:rgba(210,153,34,.2);color:#d29922;" title="MEDIUM">M:${summary.MEDIUM}</span>`);
    if ((summary.LOW      || 0) > 0) sevParts.push(`<span style="padding:1px 6px;border-radius:4px;font-size:.67rem;font-weight:700;background:rgba(88,166,255,.15);color:#58a6ff;" title="LOW">L:${summary.LOW}</span>`);
    const sevRow = project.findings_summary !== undefined
      ? `<div style="display:flex;gap:4px;margin-top:5px;flex-wrap:wrap;">${sevParts.length ? sevParts.join("") : `<span style="font-size:.67rem;color:var(--muted);">Sin hallazgos</span>`}</div>`
      : "";

    // CAMBIO 4b: scanner icon badges from last_scan_tool (e.g. "bandit+pip-audit")
    const scannerBadges = String(project.last_scan_tool || "")
      .split("+").map((s) => s.trim()).filter(Boolean)
      .map((s) => normalizeToolKey(s)).filter(Boolean)
      .map(buildScannerIconBadge);
    const scannerRow = scannerBadges.length
      ? `<div style="display:flex;gap:4px;margin-top:5px;flex-wrap:wrap;">${scannerBadges.join("")}</div>`
      : "";

    btn.innerHTML = `
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;">
        <span style="font-size:.85rem;font-weight:700;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px;">${escapeHtml(project.name)}</span>
        ${critCount > 0
          ? `<span style="flex-shrink:0;padding:1px 8px;border-radius:9999px;font-size:.7rem;font-weight:700;background:rgba(248,81,73,.15);color:#ff7b72;border:1px solid rgba(248,81,73,.3);">${critCount}</span>`
          : `<span style="flex-shrink:0;padding:1px 8px;border-radius:9999px;font-size:.7rem;font-weight:600;background:var(--bg-hover);color:var(--muted);border:1px solid var(--border);">${totalF}</span>`}
      </div>
      <div style="display:flex;gap:6px;margin-top:8px;flex-wrap:wrap;">
        <span style="padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600;${techStyle(project.technology)}">${escapeHtml(project.technology)}</span>
        <span style="padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:600;background:var(--bg-hover);color:var(--muted);border:1px solid var(--border);">${escapeHtml(String(project.source_type || "").toUpperCase())}</span>
      </div>
      ${sevRow}
      ${scannerRow}
      <p style="margin-top:5px;font-size:.7rem;color:var(--muted);">${escapeHtml(createdAt)}</p>
    `;
    btn.addEventListener("click", () => selectProject(project));
    projectsList.appendChild(btn);
  });
}

// ── Data loading ──────────────────────────────────────────────────────────────
export async function loadFindings() {
  if (!ensureServerContext()) { renderMessage("El dashboard debe abrirse desde el servidor local."); return; }
  if (!selectedProject) {
    if (currentProjectTitle) currentProjectTitle.textContent = t("select-project");
    if (tableStatus) tableStatus.textContent = t("findings-appear");
    updateCounters([]);
    renderMessage(t("select-project"));
    return;
  }
  if (refreshButton) refreshButton.disabled = true;
  if (currentProjectTitle) currentProjectTitle.textContent = selectedProject.name;
  if (tableStatus) tableStatus.textContent = "Cargando hallazgos…";

  try {
    const records = await getProjectFindings(selectedProject.id);
    currentFindings = records;
    activeScannerFilter = "all";
    updateScanStackIcons();
    renderScannerFilterIcons();
    renderRows(records);
    renderMlControls();
    if (tableStatus) {
      tableStatus.textContent = `${records.length} ${t("findings-loaded")}`;
    }
  } catch {
    currentFindings = [];
    activeScannerFilter = "all";
    updateCounters([]);
    renderMessage("No se pudieron cargar los hallazgos.");
    if (tableStatus) tableStatus.textContent = "Error al cargar hallazgos";
    if (scannerFilterEl) scannerFilterEl.style.display = "none";
  } finally {
    if (refreshButton) refreshButton.disabled = false;
  }
}

export async function loadProjects(selectFirst = true) {
  if (!ensureServerContext()) return;
  try {
    projects = await getProjects();
    await ensureScanProfilesLoaded(true);
    if (selectedProject) selectedProject = projects.find((p) => p.id === selectedProject.id) || null;
    if (!selectedProject && selectFirst && projects.length > 0) selectedProject = projects[0];
    renderProjects();
    updateScanStackIcons();
    if (selectedProject) await loadFindings();
    else { updateCounters([]); renderMessage("Selecciona o crea un proyecto para ver hallazgos."); }
  } catch (error) {
    if (projectStatus) projectStatus.textContent = "Error al cargar proyectos";
    showFeedback(`No se pudieron cargar los proyectos: ${error.message}`, "error");
  }
}

export async function selectProject(project) {
  selectedProject = project;
  projectsPopover?.classList.remove("open"); // close popover on selection
  renderProjects();
  await ensureScanProfilesLoaded();
  updateScanStackIcons();
  await loadFindings();
  if (activeView === "report") loadReport(project.id);
}

export async function loadAiStatus() {
  if (!ensureServerContext()) return;
  try {
    aiStatus = await getAiStatus();
  } catch {
    aiStatus = { available: false, reason: "Ollama service offline" };
  }
  renderAiStatusBadge();
  if (currentFindings.length > 0) renderRows(currentFindings);
}

async function ensureScanProfilesLoaded(force = false) {
  if (scanProfilesLoaded && !force) return;
  try {
    scanProfiles = await getProfiles();
  } catch {
    scanProfiles = [];
  }
  scanProfilesLoaded = true;
}

function selectedProjectProfile() {
  if (!selectedProject || selectedProject.scan_profile_id == null) return null;
  return scanProfiles.find((profile) => profile.id === selectedProject.scan_profile_id) || null;
}

const _SI = (d) => `<svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true">${d}</svg>`;
const STACK_ICON_META = {
  python: {
    label: "Python", tone: "python",
    icon: _SI(`<path fill="currentColor" d="M7.5 2C5.5 2 4.5 3 4.5 4V5.5H7.5V6H4C3 6 2.5 6.8 2.5 7.5S3 9 4 9H5V7.5H7.5V7H5.5V6.5H7.5C8.5 6.5 9 6 9 5V4C9 3 8 2 7.5 2ZM6.5 3.5A.5.5 0 116.5 4.5.5.5 0 016.5 3.5Z"/><path fill="currentColor" d="M8.5 14C10.5 14 11.5 13 11.5 12V10.5H8.5V10H12C13 10 13.5 9.2 13.5 8.5S13 7 12 7H11V8.5H8.5V9H10.5V9.5H8.5C7.5 9.5 7 10 7 11V12C7 13 8 14 8.5 14ZM9.5 12.5A.5.5 0 119.5 11.5.5.5 0 019.5 12.5Z"/>`)
  },
  angular: {
    label: "Angular", tone: "angular",
    icon: _SI(`<path fill="currentColor" d="M8 1.5L2 13H4L5.5 9.5H10.5L12 13H14L8 1.5ZM8 5L10 9H6L8 5Z"/>`)
  },
  typescript: {
    label: "TypeScript", tone: "typescript",
    icon: _SI(`<rect fill="currentColor" x="1.5" y="1.5" width="13" height="13" rx="2"/><path fill="#0f172a" d="M3.5 5.5H12.5V7.5H9.5V13H7V7.5H3.5V5.5Z"/>`)
  },
  java: {
    label: "Java", tone: "java",
    icon: _SI(`<path fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" d="M5 2C5 4.5 7.5 5 6 7.5M7.5 1.5C7.5 3.5 9.5 4.5 8.5 7M10 2.5C10 4.5 12 5 11 7"/><path fill="none" stroke="currentColor" stroke-width="1.3" d="M4 9c0 .5 1 .5 4 .5s4 0 4-.5-1-.5-4-.5-4 0-4 .5Z"/><path fill="none" stroke="currentColor" stroke-width="1.2" d="M5 11c0 .4.8.4 3 .4s3-.4 3-.4-1-.4-3-.4-3 0-3 .4ZM5.5 13c0 .3.7.5 2.5.5s2.5-.2 2.5-.5-.7-.5-2.5-.5-2.5.2-2.5.5Z"/>`)
  },
  semgrep: {
    label: "Semgrep", tone: "sast",
    icon: _SI(`<circle cx="7" cy="7" r="4.5" fill="none" stroke="currentColor" stroke-width="1.5"/><line x1="10.5" y1="10.5" x2="13.5" y2="13.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><path fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" d="M5 7h4M7 5v4"/>`)
  },
  bandit: {
    label: "Bandit", tone: "sast",
    icon: _SI(`<path fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" d="M8 1.5L2.5 4V9C2.5 12.5 5.5 14.5 8 15 10.5 14.5 13.5 12.5 13.5 9V4L8 1.5Z"/><line x1="8" y1="5.5" x2="8" y2="9.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/><circle cx="8" cy="11.2" r=".8" fill="currentColor"/>`)
  },
  zap: {
    label: "OWASP ZAP", tone: "dast",
    icon: _SI(`<path fill="currentColor" d="M9.5 1.5L4 9H8.5L6 14.5L13.5 7H8.5L9.5 1.5Z"/>`)
  },
  pylint: {
    label: "Pylint", tone: "quality",
    icon: _SI(`<circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="1.4"/><path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" d="M5 8l2.5 2.5L11 6"/>`)
  },
  eslint: {
    label: "ESLint", tone: "quality",
    icon: _SI(`<path fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" d="M8 1.5L2 5V11L8 14.5L14 11V5L8 1.5Z"/><path fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" d="M5 6.5H11M5 8H9.5M5 9.5H11"/>`)
  },
  sonarqube: {
    label: "SonarQube", tone: "quality",
    icon: _SI(`<path fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" d="M3 12C3 9 5.7 6.5 9 6.5M3 12C3 6 6.8 2.5 12 2.5M3 12H13"/>`)
  },
  "pip-audit": {
    label: "pip-audit", tone: "sca",
    icon: _SI(`<rect x="2.5" y="5.5" width="11" height="8" rx="1" fill="none" stroke="currentColor" stroke-width="1.4"/><path fill="none" stroke="currentColor" stroke-width="1.3" d="M5.5 5.5V4A1.5 1.5 0 017 2.5H9A1.5 1.5 0 0110.5 4V5.5"/><path fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round" d="M6 10l1.5 1.5 3-2.5"/>`)
  },
  odc: {
    label: "Dep Check", tone: "sca",
    icon: _SI(`<path fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" d="M8 1.5L2.5 4.5V10C2.5 13 5.5 15 8 15 10.5 15 13.5 13 13.5 10V4.5L8 1.5Z"/><path fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" d="M5.5 8.5l2 2 3.5-3.5"/>`)
  },
  checkov: {
    label: "Checkov", tone: "infra",
    icon: _SI(`<rect x="2" y="2" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><rect x="9" y="2" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><rect x="2" y="9" width="5" height="5" rx="1" fill="none" stroke="currentColor" stroke-width="1.3"/><path fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" d="M9.5 11.5l1.5 1.5 3-3"/>`)
  },
  trivy: {
    label: "Trivy", tone: "infra",
    icon: _SI(`<path fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" d="M8 1.5L2 5V11L8 14.5L14 11V5L8 1.5Z"/><path fill="currentColor" d="M8 5.5A2.5 2.5 0 118 10.5 2.5 2.5 0 018 5.5Z"/>`)
  },
  gitleaks: {
    label: "Gitleaks", tone: "infra",
    icon: _SI(`<circle cx="8" cy="6" r="3" fill="none" stroke="currentColor" stroke-width="1.4"/><path fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" d="M8 9v5M6 12h4"/><circle cx="8" cy="6" r="1" fill="currentColor"/>`)
  },
};

function addStackItem(items, key, source = "scan") {
  const meta = STACK_ICON_META[key];
  if (!meta || items.some((item) => item.key === key)) return;
  items.push({ key, source, ...meta });
}

function normalizeToolKey(value) {
  const text = String(value || "").toLowerCase();
  if (text.includes("semgrep")) return "semgrep";
  if (text.includes("bandit")) return "bandit";
  if (text.includes("zap")) return "zap";
  if (text.includes("pylint")) return "pylint";
  if (text.includes("eslint")) return "eslint";
  if (text.includes("sonar")) return "sonarqube";
  if (text.includes("pip")) return "pip-audit";
  if (text.includes("dependency") || text.includes("odc")) return "odc";
  if (text.includes("checkov")) return "checkov";
  if (text.includes("trivy")) return "trivy";
  if (text.includes("gitleaks")) return "gitleaks";
  return "";
}

function buildScanStackItems() {
  const items = [];
  if (!selectedProject) return items;

  addStackItem(items, String(selectedProject.technology || "").toLowerCase(), "tech");

  const profile = selectedProjectProfile();
  if (profile?.sast_enabled) {
    if (profile.sast_tools === "both") {
      addStackItem(items, "semgrep", "sast");
      addStackItem(items, "bandit", "sast");
    } else {
      addStackItem(items, normalizeToolKey(profile.sast_tools || "semgrep"), "sast");
    }
  }
  if (profile?.dast_enabled) addStackItem(items, normalizeToolKey(profile.dast_tool || "zap"), "dast");
  if (profile?.quality_enabled) addStackItem(items, normalizeToolKey(profile.quality_tool), "quality");
  if (profile?.infra_enabled && profile?.infra_tools) {
    (profile.infra_tools).split(",").map((t) => t.trim()).filter(Boolean).forEach((t) => {
      addStackItem(items, normalizeToolKey(t), "infra");
    });
  }

  addStackItem(items, normalizeToolKey(selectedProject.last_scan_tool), "scan");
  currentFindings.forEach((finding) => {
    addStackItem(items, normalizeToolKey(finding.tool || detectTool(finding)), "finding");
  });

  return items;
}

function updateScanStackIcons() {
  if (!scanStackIcons) return;
  scanStackIcons.innerHTML = "";

  if (!selectedProject) {
    scanStackIcons.innerHTML = `<span class="scan-stack-empty">Sin proyecto</span>`;
    return;
  }

  const profile = selectedProjectProfile();
  if (profile) {
    const profileEl = document.createElement("span");
    profileEl.className = "scan-stack-profile";
    profileEl.title = `Perfil: ${profile.name}`;
    profileEl.innerHTML = `<svg width="11" height="11" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="2" y="3" width="12" height="2" rx="1" fill="currentColor"/><rect x="2" y="7" width="8" height="2" rx="1" fill="currentColor"/><rect x="2" y="11" width="10" height="2" rx="1" fill="currentColor"/></svg>${escapeHtml(profile.name)}`;
    scanStackIcons.appendChild(profileEl);
  }

  const items = buildScanStackItems();
  if (!items.length) return;

  items.forEach((item) => {
    const badge = document.createElement("span");
    badge.className = `scan-stack-chip ${item.tone}`;
    badge.title = item.label;
    badge.innerHTML = `<span class="scan-stack-icon">${item.icon}</span><span class="scan-stack-label">${escapeHtml(item.label)}</span>`;
    scanStackIcons.appendChild(badge);
  });
}

// ── Agentic DAST flow ────────────────────────────────────────────────────────

const _DAST_STATUS_LABELS = {
  exploring: "🤖 Explorando rutas",
  attacking: "🤖 Atacando endpoints",
  verifying: "🤖 Verificando hallazgos",
  done: "🤖 Agentic DAST completado",
  error: "🤖 Agentic DAST con error",
};

function _showDastFeedback(result, finalStatus) {
  const detailedError = finalStatus?.error || result.error;
  if (result.status === "error") {
    const iters = result.iterations_run || 0;
    const iterSuffix = iters > 0 ? ` (${iters} iteración(es))` : "";
    showFeedback(`Agentic DAST falló${iterSuffix}: ${detailedError || "fallo desconocido"}`, "warning");
    return;
  }
  const n = (result.confirmed_findings || []).length;
  const fp = result.false_positives_count || 0;
  const iters = result.iterations_run || 0;
  const warnings = result.warnings || finalStatus?.warnings || [];
  if (warnings.length > 0) {
    const suffix = ` · ${n} confirmados`;
    showFeedback(`Agentic DAST completado con avisos: ${warnings[0]}${suffix}`, "warning");
  } else if (n === 0 && iters === 0) {
    showFeedback("Agentic DAST — 0 iteraciones completadas (sin rutas descubiertas o target inalcanzable)", "info");
  } else {
    showFeedback(`Agentic DAST OK — ${n} confirmados · ${fp} falsos positivos · ${iters} iteración(es)`, n > 0 ? "success" : "info");
  }
}

async function runAgenticDastFlow(dastTargetUrl) {
  if (!dastTargetUrl) {
    showFeedback("Agentic DAST necesita una URL. Salta este paso.", "warning");
    return { aborted: false };
  }
  const iterRaw = globalThis.prompt("Iteraciones del agente (1-5):", "3");
  const maxIterations = Math.max(1, Math.min(Number.parseInt(iterRaw || "3", 10) || 3, 5));

  if (scanStatus) scanStatus.textContent = "🤖 Agentic DAST en curso";
  showFeedback("LangGraph agentic loop iniciado — Exploring…", "info");

  let pollHandle = null;
  try {
    const agenticPromise = runAgenticDastScan({
      targetUrl: dastTargetUrl,
      projectId: selectedProject.id,
      maxIterations,
    });

    let lastScanId = null;
    pollHandle = setInterval(async () => {
      if (!lastScanId) return;
      const status = await getAgenticDastStatus(lastScanId).catch(() => null);
      if (status?.status) {
        if (scanStatus) scanStatus.textContent = _DAST_STATUS_LABELS[status.status] || "🤖 Agentic DAST";
      }
    }, 2000);

    const result = await agenticPromise;
    lastScanId = result.scan_id;

    const finalStatus = lastScanId
      ? await getAgenticDastStatus(lastScanId).catch(() => null)
      : null;

    _showDastFeedback(result, finalStatus);
  } catch (err) {
    const detail = err?.detail || err?.message || "error desconocido";
    showFeedback(`Agentic DAST falló: ${detail}`, "warning");
  } finally {
    if (pollHandle) clearInterval(pollHandle);
  }
  return { aborted: false };
}


// ── Scan ──────────────────────────────────────────────────────────────────────
export async function runScan() {
  if (!ensureServerContext()) return;
  if (!selectedProject) { showFeedback("Selecciona un proyecto antes de escanear.", "error"); return; }

  if (refreshButton) refreshButton.disabled = true;
  if (panelRunScanButton) {
    panelRunScanButton.disabled = true;
    panelRunScanButton.innerHTML = `<span class="spinner"></span> Escaneando…`;
  }
  if (scanStatus) scanStatus.textContent = "En progreso";
  if (tableStatus) tableStatus.textContent = "Ejecutando scanner…";
  showFeedback("Escaneo en curso. El scanner está analizando el código.", "info");

  try {
    await ensureScanProfilesLoaded();
    const profile = selectedProjectProfile();
    let dastTargetUrl = null;
    if (profile?.dast_enabled) {
      dastTargetUrl = window.prompt("URL del objetivo DAST (ej: http://host.docker.internal:8000) — usar host.docker.internal en lugar de 127.0.0.1 o localhost:") || null;
    }

    if (profile?.dast_enabled && profile?.dast_tool === "agent_loop") {
      const agenticResult = await runAgenticDastFlow(dastTargetUrl);
      if (agenticResult.aborted) return;
      // After the agentic flow finishes, fall through to a normal SAST/Quality scan
      // so the SAST + Quality runners still produce findings for this project.
    }

    const result = await scanProject(selectedProject.id, dastTargetUrl);
    if (!result.success) throw new Error(result.error || "Scan failed");
    const finishedAt = new Date().toLocaleTimeString();
    const saved = result.saved_findings ?? 0;
    if (scanStatus) scanStatus.textContent = `${saved} guardados`;

    const msgParts = [];
    if (saved === 0) {
      msgParts.push("Sin hallazgos nuevos encontrados.");
    } else {
      const plural = saved === 1 ? "" : "s";
      msgParts.push(`${saved} hallazgo${plural} guardado${plural}.`);
    }
    if (result.scan_summary && Object.keys(result.scan_summary).length > 0) {
      const summaryStr = Object.entries(result.scan_summary)
        .map(([tool, count]) => `${tool}: ${count}`).join(" · ");
      msgParts.push(`[${summaryStr}]`);
    }
    if (result.warnings?.length) {
      msgParts.push(`ℹ ${result.warnings.join("; ")}`);
    }
    if (result.errors?.length) {
      msgParts.push(`⚠ ${result.errors.join("; ")}`);
    }
    let feedbackType;
    if (result.errors?.length) {
      feedbackType = "warning";
    } else if (saved === 0 && !result.warnings?.length) {
      feedbackType = "info";
    } else {
      feedbackType = "success";
    }
    showFeedback(
      `Escaneo completado a las ${finishedAt}. ${msgParts.join(" ")}`,
      feedbackType,
    );
    await loadProjects(false);
    await loadFindings();
  } catch (error) {
    if (scanStatus) scanStatus.textContent = "Error";
    if (tableStatus) tableStatus.textContent = "No se pudo ejecutar el escaneo";
    showFeedback(`No se pudo ejecutar el escaneo: ${error.message}`, "error");
  } finally {
    if (refreshButton) refreshButton.disabled = false;
    if (panelRunScanButton) {
      panelRunScanButton.disabled = false;
      panelRunScanButton.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
          <path d="M4 3 L13 8 L4 13 Z" fill="currentColor"/>
        </svg>
        Run new scan
      `;
      applyI18n();
    }
  }
}

// ── Remediate ─────────────────────────────────────────────────────────────────
export async function remediateFinding(record, button) {
  if (!aiStatus.available) {
    showFeedback("AI Engine offline: inicia Ollama para generar remediaciones locales.", "error");
    return;
  }
  const origHtml = button.innerHTML;
  button.disabled = true;
  button.innerHTML = `<span class="spinner"></span> Pensando…`;
  showFeedback("El motor de IA está generando una remediación sugerida.", "info");

  try {
    const result = await generateRemediation(record.id);
    record.has_remediation = true;
    showRemediationModal(record, result.patch || "No patch was returned.", selectedProject);

    if (result.validation_warning) {
      // Patch was saved but failed full validation — open modal with a warning
      showFeedback(
        `⚠ El parche requiere revisión manual antes de aplicarse: ${result.validation_warning}`,
        "warning"
      );
    } else {
      const msg = result.cached
        ? "Remediación recuperada del caché — no se llamó a Ollama."
        : "Remediación generada y guardada.";
      showFeedback(msg, "success");
    }
  } catch (error) {
    showFeedback(
      `No se pudo generar la remediación: ${formatApiError(error.detail, error.message)}`,
      "error"
    );
  } finally {
    button.disabled = false;
    button.innerHTML = origHtml;
  }
}

// ── Report view ───────────────────────────────────────────────────────────────
export function setView(view) {
  activeView = view;
  if (view === "findings") {
    if (findingsTableView) findingsTableView.style.display = "";
    if (findingsReportView) findingsReportView.style.display = "none";
    if (viewFindingsBtn) { viewFindingsBtn.style.background = "var(--t-hi)"; viewFindingsBtn.style.color = "var(--bg)"; }
    if (viewReportBtn) { viewReportBtn.style.background = "transparent"; viewReportBtn.style.color = "var(--t-dim)"; }
    if (exportPdfBtn) exportPdfBtn.style.display = "none";
    document.querySelectorAll(".nav .links a").forEach((a) => a.classList.remove("on"));
    document.querySelector(".nav .links a:first-child")?.classList.add("on");
  } else {
    if (findingsTableView) findingsTableView.style.display = "none";
    if (findingsReportView) findingsReportView.style.display = "";
    if (viewFindingsBtn) { viewFindingsBtn.style.background = "transparent"; viewFindingsBtn.style.color = "var(--t-dim)"; }
    if (viewReportBtn) { viewReportBtn.style.background = "var(--t-hi)"; viewReportBtn.style.color = "var(--bg)"; }
    if (exportPdfBtn) exportPdfBtn.style.display = "flex";
    document.querySelectorAll(".nav .links a").forEach((a) => a.classList.remove("on"));
    document.querySelector(".nav .links a:nth-child(4)")?.classList.add("on");
    if (selectedProject) loadReport(selectedProject.id);
  }
}

export async function loadReport(projectId) {
  if (reportLoading) { reportLoading.style.display = ""; reportLoading.textContent = "Cargando reporte…"; }
  if (reportContent) reportContent.style.display = "none";
  try {
    const data = await getReport(projectId);
    renderReport(data);
  } catch (e) {
    if (reportLoading) reportLoading.textContent = `Error cargando reporte: ${e.message}`;
  }
}

function renderReport(data) {
  if (reportLoading) reportLoading.style.display = "none";
  if (reportContent) reportContent.style.display = "";
  setText("report-total", data.total_findings);
  setText("report-crit-high",
    (data.by_severity["CRITICAL"] || 0) + (data.by_severity["HIGH"] || 0));
  setText("report-overdue", data.overdue_count || 0);

  const chartDefaults = {
    responsive: true,
    plugins: { legend: { labels: { color: "#8b949e", font: { size: 11 } } } },
    scales: {
      x: { ticks: { color: "#8b949e" }, grid: { color: "#30363d" } },
      y: { ticks: { color: "#8b949e" }, grid: { color: "#30363d" } },
    },
  };

  if (chartSeverity) chartSeverity.destroy();
  chartSeverity = new Chart(document.getElementById("chart-severity"), {
    type: "bar",
    data: {
      labels: ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
      datasets: [{
        data: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => data.by_severity[s] || 0),
        backgroundColor: ["#ef4444", "#dc2626", "#d29922", "#3b82f6"],
        borderRadius: 4,
      }],
    },
    options: { ...chartDefaults, plugins: { ...chartDefaults.plugins, legend: { display: false } } },
  });

  const statusLabels = Object.keys(data.by_status);
  const statusColors = statusLabels.map((s) => ({
    open: "#2f81f7", fixed: "#3fb950", regression: "#f85149",
    accepted_risk: "#8b949e", false_positive: "#8b949e",
  }[s] || "#58a6ff"));
  if (chartStatus) chartStatus.destroy();
  chartStatus = new Chart(document.getElementById("chart-status"), {
    type: "doughnut",
    data: {
      labels: statusLabels,
      datasets: [{ data: statusLabels.map((s) => data.by_status[s]), backgroundColor: statusColors, borderWidth: 0 }],
    },
    options: { responsive: true, plugins: { legend: { labels: { color: "#8b949e", font: { size: 11 } } } } },
  });

  if (chartRules) chartRules.destroy();
  chartRules = new Chart(document.getElementById("chart-rules"), {
    type: "bar",
    data: {
      labels: data.top_rules.map((r) => r.rule_id),
      datasets: [{ data: data.top_rules.map((r) => r.count), backgroundColor: "#2f81f7", borderRadius: 4 }],
    },
    options: {
      indexAxis: "y", ...chartDefaults,
      plugins: { ...chartDefaults.plugins, legend: { display: false } },
    },
  });
}

// ── PDF export ────────────────────────────────────────────────────────────────
function buildPdfHtml(project, reportData, findings, sevImg, statusImg, rulesImg) {
  const date = new Date().toLocaleDateString("es-MX", { year: "numeric", month: "long", day: "numeric" });
  const byS = reportData.by_severity || {};
  const byStatus = reportData.by_status || {};
  const totalFindings = reportData.total_findings ?? findings.length;
  const overdueCount = reportData.overdue_count || 0;
  const withinSla = totalFindings - overdueCount;
  const sev = (s) => byS[s] || 0;

  const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted   = [...findings].sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));
  const top50    = sorted.slice(0, 50); // canvas memory limit: cap at 50 rows

  const findingsRows = top50.map((f) => {
    const deadline = f.sla_deadline ? new Date(f.sla_deadline).toLocaleDateString("es-MX") : "—";
    const filePath = (f.file_path || "—").replace(/.*\/repo\//, "").replace(/.*\/source\//, "");
    const sevColor = ({ CRITICAL: "#dc2626", HIGH: "#991b1b", MEDIUM: "#b45309", LOW: "#1d4ed8" })[f.severity] || "#555";
    return `<tr>
      <td style="font-family:monospace;font-size:10px;">${String(f.id || "").slice(0, 8)}</td>
      <td style="color:${sevColor};font-weight:700;white-space:nowrap;">${f.severity || "—"}</td>
      <td style="font-size:10px;word-break:break-all;">${escapeHtml(filePath)}</td>
      <td style="font-size:10px;font-family:monospace;">${escapeHtml((f.rule_id || "—").slice(0, 30))}</td>
      <td style="font-size:10px;">${escapeHtml((f.description || "—").slice(0, 70))}</td>
      <td style="white-space:nowrap;">${escapeHtml(f.status || "open")}</td>
      <td style="white-space:nowrap;">${escapeHtml(deadline)}</td>
    </tr>`;
  }).join("");

  const statusRows = Object.entries(byStatus).map(([s, c]) =>
    `<tr><td>${escapeHtml(s)}</td><td style="font-weight:700;">${c}</td></tr>`
  ).join("");

  const chartsSection = (sevImg || statusImg || rulesImg) ? `
    <div class="section">
      <h2 class="section-title">2. Gráficas</h2>
      <div style="display:grid;grid-template-columns:${sevImg && statusImg ? "1fr 1fr" : "1fr"};gap:16px;margin-bottom:16px;">
        ${sevImg ? `<div class="card"><p class="card-title">Por Severidad</p><img src="${sevImg}" style="width:100%;max-height:200px;object-fit:contain;background:#fff;"></div>` : ""}
        ${statusImg ? `<div class="card"><p class="card-title">Por Estado</p><img src="${statusImg}" style="width:100%;max-height:200px;object-fit:contain;background:#fff;"></div>` : ""}
      </div>
      ${rulesImg ? `<div class="card"><p class="card-title">Top Reglas</p><img src="${rulesImg}" style="width:100%;max-height:180px;object-fit:contain;background:#fff;"></div>` : ""}
    </div>` : "";

  return `
    <style>
      *{box-sizing:border-box;margin:0;padding:0;}
      body{font-family:Arial,sans-serif;color:#1a1a2e;background:#fff;font-size:12px;}
      .cover{background:#1e3a5f;color:#fff;padding:36px 32px 28px;}
      .cover-platform{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:#90b8e0;margin-bottom:10px;}
      .cover-title{font-size:26px;font-weight:800;margin-bottom:4px;}
      .cover-sub{font-size:15px;color:#a0c8f0;margin-bottom:28px;}
      .cover-meta{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
      .meta-item{background:rgba(255,255,255,.1);padding:10px 14px;border-radius:6px;}
      .meta-label{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:#90b8e0;margin-bottom:3px;}
      .meta-value{font-size:14px;font-weight:700;}
      .sev-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:16px 32px;background:#f4f6fa;border-bottom:2px solid #dde3ed;}
      .sev-card{text-align:center;padding:10px;border-radius:6px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.08);}
      .sev-num{font-size:24px;font-weight:800;}
      .sev-label{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:#666;margin-top:2px;}
      .section{padding:16px 32px;border-bottom:1px solid #dde3ed;}
      .section-title{font-size:14px;font-weight:800;color:#1e3a5f;margin-bottom:14px;padding-bottom:6px;border-bottom:2px solid #1e3a5f;}
      table{width:100%;border-collapse:collapse;font-size:11px;}
      th{background:#1e3a5f;color:#fff;padding:7px 10px;text-align:left;font-size:9px;text-transform:uppercase;letter-spacing:.05em;}
      td{padding:7px 10px;border-bottom:1px solid #e8ecf2;vertical-align:top;}
      tr:nth-child(even) td{background:#f8f9fb;}
      .card{background:#f4f6fa;border:1px solid #dde3ed;border-radius:6px;padding:14px;}
      .card-title{font-size:11px;font-weight:700;color:#1e3a5f;margin-bottom:10px;}
      .note{font-size:10px;color:#888;font-style:italic;text-align:center;padding:8px;margin-top:6px;}
    </style>

    <div class="cover">
      <div class="cover-platform">AI DevSecOps Control Plane</div>
      <div class="cover-title">Reporte de Seguridad</div>
      <div class="cover-sub">${escapeHtml(project.name)}</div>
      <div class="cover-meta">
        <div class="meta-item"><div class="meta-label">Fecha</div><div class="meta-value">${date}</div></div>
        <div class="meta-item"><div class="meta-label">Total hallazgos</div><div class="meta-value">${totalFindings}</div></div>
        <div class="meta-item"><div class="meta-label">Dentro de SLA</div><div class="meta-value">${withinSla}</div></div>
        <div class="meta-item"><div class="meta-label">SLA vencidos</div><div class="meta-value">${overdueCount}</div></div>
      </div>
    </div>

    <div class="sev-strip">
      <div class="sev-card"><div class="sev-num" style="color:#dc2626;">${sev("CRITICAL")}</div><div class="sev-label">Critical</div></div>
      <div class="sev-card"><div class="sev-num" style="color:#991b1b;">${sev("HIGH")}</div><div class="sev-label">High</div></div>
      <div class="sev-card"><div class="sev-num" style="color:#b45309;">${sev("MEDIUM")}</div><div class="sev-label">Medium</div></div>
      <div class="sev-card"><div class="sev-num" style="color:#1d4ed8;">${sev("LOW")}</div><div class="sev-label">Low</div></div>
    </div>

    <div class="section">
      <h2 class="section-title">1. Resumen por Estado</h2>
      <table>
        <tr><th>Estado</th><th>Cantidad</th></tr>
        ${statusRows}
      </table>
    </div>

    ${chartsSection}

    <div class="section pdf-findings-section">
      <h2 class="section-title">3. Lista de Hallazgos — Top ${top50.length} de ${sorted.length} (ordenados por severidad)</h2>
      <table>
        <tr>
          <th style="width:64px;">ID</th>
          <th style="width:76px;">Severidad</th>
          <th style="width:130px;">Archivo</th>
          <th style="width:110px;">Regla</th>
          <th>Descripción</th>
          <th style="width:72px;">Estado</th>
          <th style="width:72px;">SLA</th>
        </tr>
        ${findingsRows}
      </table>
      <p class="note">Mostrando todos los hallazgos encontrados en el scan. Ordenados por severidad descendente.</p>
    </div>`;
}

export async function exportToPDF() {
  if (!selectedProject) { showFeedback("Selecciona un proyecto para exportar.", "error"); return; }
  const labelEl = document.getElementById("export-pdf-label");
  if (exportPdfBtn) exportPdfBtn.disabled = true;
  if (labelEl) labelEl.textContent = "Generando…";

  try {
    const [reportData, allFindings] = await Promise.all([
      getReport(selectedProject.id),
      getProjectFindings(selectedProject.id),
    ]);

    // Render chart canvases onto a white backing to avoid dark-theme transparency → black JPEG
    const chartToWhitePng = (chart) => {
      if (!chart) return null;
      const src = chart.canvas;
      const tmp = document.createElement("canvas");
      tmp.width = src.width; tmp.height = src.height;
      const ctx = tmp.getContext("2d");
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, tmp.width, tmp.height);
      ctx.drawImage(src, 0, 0);
      return tmp.toDataURL("image/png");
    };
    const sevImg    = chartToWhitePng(chartSeverity);
    const statusImg = chartToWhitePng(chartStatus);
    const rulesImg  = chartToWhitePng(chartRules);

    const { jsPDF } = window.jspdf;
    const doc   = new jsPDF({ format: "a4", unit: "px", hotfixes: ["px_scaling"] });
    const pageW = doc.internal.pageSize.getWidth();
    const pageH = doc.internal.pageSize.getHeight();

    const ML = 44, MT = 32, MB = 48;
    const contentW = pageW - 2 * ML;
    const usableH  = pageH - MT - MB;

    const today = new Date().toLocaleDateString("es-MX");
    let pageNum = 1;
    let hasRenderedPage = false;

    const renderPdfSection = async (sectionName) => {
      const containerW = Math.floor(contentW);
      const container  = document.createElement("div");
      container.style.cssText =
        `position:absolute;left:-9999px;top:0;width:${containerW}px;` +
        `background:#ffffff;color:#1a1a2e;font-family:Arial,sans-serif;`;
      container.innerHTML = buildPdfHtml(selectedProject, reportData, allFindings, sevImg, statusImg, rulesImg);

      if (sectionName === "summary") {
        container.querySelector(".pdf-findings-section")?.remove();
      } else if (sectionName === "findings") {
        Array.from(container.children).forEach((child) => {
          const isStyle    = child.tagName.toLowerCase() === "style";
          const isFindings = child.classList.contains("pdf-findings-section");
          if (!isStyle && !isFindings) child.remove();
        });
      }

      document.body.appendChild(container);
      const canvas = await html2canvas(container, {
        scale: 2, backgroundColor: "#ffffff", useCORS: true, allowTaint: true, logging: false,
      });
      document.body.removeChild(container);

      const ratio  = canvas.width / contentW;
      const pageHpx = Math.floor(usableH * ratio);
      let yOffset = 0;

      while (yOffset < canvas.height) {
        if (hasRenderedPage) doc.addPage();
        const remaining = canvas.height - yOffset;
        const sliceH    = Math.min(pageHpx, remaining);
        const sliceCanvas = document.createElement("canvas");
        sliceCanvas.width  = canvas.width;
        sliceCanvas.height = sliceH;
        const sCtx = sliceCanvas.getContext("2d");
        sCtx.fillStyle = "#ffffff"; // white fill — prevents transparent→black on JPEG export
        sCtx.fillRect(0, 0, sliceCanvas.width, sliceCanvas.height);
        sCtx.drawImage(canvas, 0, -yOffset);
        const imgData = sliceCanvas.toDataURL("image/jpeg", 0.93);
        const imgH = sliceH / ratio;
        doc.addImage(imgData, "JPEG", ML, MT, contentW, imgH);
        const footerY = MT + usableH + MB / 2;
        doc.setFontSize(7);
        doc.setTextColor(160, 160, 160);
        doc.text(`Generado por AI DevSecOps Control Plane · ${today} · Confidencial`, ML + 4, footerY);
        doc.text(`Página ${pageNum}`, pageW - ML - 4, footerY, { align: "right" });
        yOffset += pageHpx;
        pageNum++;
        hasRenderedPage = true;
      }
    };

    await renderPdfSection("summary");
    await renderPdfSection("findings");

    const safeName = selectedProject.name.replace(/[^a-zA-Z0-9-_]/g, "-").slice(0, 40);
    const dateStr  = new Date().toISOString().split("T")[0];
    doc.save(`security-report-${safeName}-${dateStr}.pdf`);
    showFeedback("PDF exportado correctamente.", "success");
  } catch (e) {
    showFeedback(`Error exportando PDF: ${e.message}`, "error");
  } finally {
    if (exportPdfBtn) {
      exportPdfBtn.disabled = false;
      exportPdfBtn.style.display = "flex";
    }
    if (labelEl) labelEl.textContent = t("btn-export-pdf") || "Exportar como PDF";
  }
}

// ── ML risk controls ──────────────────────────────────────────────────────────
async function retrainModel() {
  const btn = document.getElementById("ml-retrain-btn");
  const orig = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "⏳ Entrenando…"; }
  try {
    const m = await trainRiskModel();
    showFeedback(
      `${t("retrain-success")}: P=${(m.precision * 100).toFixed(0)}% R=${(m.recall * 100).toFixed(0)}% AUC=${m.roc_auc.toFixed(2)} (n=${m.n_samples})`,
      "success"
    );
    await loadFindings();
  } catch (err) {
    const detail = err?.detail || err?.message || "error desconocido";
    showFeedback(`${t("retrain-error")}: ${detail}`, "error");
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = orig; }
  }
}

function renderMlControls() {
  const existingWrap = document.getElementById("ml-controls-wrap");
  if (existingWrap) existingWrap.remove();

  if (!refreshButton?.parentElement) return;

  const wrap = document.createElement("div");
  wrap.id = "ml-controls-wrap";
  wrap.style.cssText = "display:inline-flex;align-items:center;gap:8px;margin-left:8px;";

  const btnBase =
    "display:inline-flex;align-items:center;gap:5px;border:1px solid var(--border-2);" +
    "cursor:pointer;border-radius:8px;padding:5px 9px;font-size:11.5px;font-weight:500;" +
    "transition:background .12s,color .12s,border-color .12s;background:var(--surface-2);";

  const sortBtn = document.createElement("button");
  sortBtn.type = "button";
  sortBtn.id = "ml-sort-btn";
  sortBtn.style.cssText = btnBase +
    (sortByRisk
      ? "color:var(--mint,#9effe0);border-color:rgba(158,255,224,.28);"
      : "color:var(--t-dim);");
  sortBtn.title = sortByRisk ? t("sort-severity") : t("sort-risk");
  sortBtn.textContent = sortByRisk ? t("sort-severity") : t("sort-risk");
  sortBtn.addEventListener("click", () => {
    sortByRisk = !sortByRisk;
    currentPage = 1;
    filteredFindings = getFilteredSorted(currentFindings, activeFilter);
    renderPage();
    renderMlControls();
  });
  wrap.appendChild(sortBtn);

  const retrainBtn = document.createElement("button");
  retrainBtn.type = "button";
  retrainBtn.id = "ml-retrain-btn";
  retrainBtn.style.cssText = btnBase + "color:var(--t-dim);";
  retrainBtn.textContent = t("btn-retrain-model");
  retrainBtn.addEventListener("click", retrainModel);
  wrap.appendChild(retrainBtn);

  refreshButton.after(wrap);
}

// ── Event wiring (called from main.js) ───────────────────────────────────────
export function wireDashboardEvents() {
  if (panelRunScanButton) panelRunScanButton.addEventListener("click", runScan);
  if (refreshButton)      refreshButton.addEventListener("click", loadFindings);

  projectSelect?.addEventListener("change", async () => {
    const project = projects.find((p) => String(p.id) === String(projectSelect.value));
    if (project) await selectProject(project);
  });

  document.querySelectorAll(".nav .links a[data-dashboard-view-link]").forEach((link, idx) => {
    link.addEventListener("click", (e) => {
      e.preventDefault();
      setView(idx === 3 ? "report" : "findings");
    });
  });

  if (viewFindingsBtn) viewFindingsBtn.addEventListener("click", () => setView("findings"));
  if (viewReportBtn)   viewReportBtn.addEventListener("click",   () => setView("report"));
  if (exportPdfBtn)    exportPdfBtn.addEventListener("click",    exportToPDF);

  document.getElementById("chip-all")?.addEventListener("click", () => setActiveChip("all"));
  document.getElementById("chip-critical")?.addEventListener("click", () => setActiveChip("critical"));
  document.getElementById("chip-high")?.addEventListener("click", () => setActiveChip("high"));
  document.getElementById("chip-breach")?.addEventListener("click", () => setActiveChip("breach"));

  // ── Projects-popover toggle ───────────────────────────────────────────────
  repoDiv?.addEventListener("click", (e) => {
    if (e.target === projectSelect) return; // let native <select> handle itself
    projectsPopover?.classList.toggle("open");
  });

  // Close popover on outside click
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".repo-wrap")) {
      projectsPopover?.classList.remove("open");
    }
  });

  // Close popover on Escape
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      projectsPopover?.classList.remove("open");
    }
  });
}
