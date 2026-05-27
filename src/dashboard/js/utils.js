// utils.js — i18n, shared helpers, icon SVGs (no DOM state dependencies)

// ── i18n ──────────────────────────────────────────────────────────────────
export const i18n = {
  es: {
    "findings-across":    "hallazgos en",
    "new-project":        "Nuevo Proyecto",
    "scan-project":       "▶ Escanear Proyecto",
    "projects":           "Proyectos",
    "registered-projects":"proyectos registrados",
    "findings-loaded":    "hallazgos cargados",
    "refresh":            "Actualizar",
    "not-executed":       "Sin ejecutar",
    "last-scan":          "Último escaneo",
    "open-findings":      "Hallazgos abiertos",
    "convert-pr":         "Convertir a Pull Request",
    "delete-branch":      "Eliminar Rama",
    "suggested-remediation": "Remediación sugerida",
    "vulnerable-code":    "Código vulnerable",
    "proposed-code":      "Código seguro propuesto",
    "upload-zip":         "Subir ZIP",
    "clone-repo":         "Clonar Repo",
    "project-name":       "Nombre del proyecto",
    "clone-scan":         "Clonar y Escanear",
    "create-from-zip":    "Crear desde ZIP",
    "select-project":     "Selecciona un proyecto",
    "findings-appear":    "Los hallazgos aparecerán aquí.",
    "no-findings":        "Sin hallazgos detectados para este proyecto.",
    "nav-overview":       "Resumen",
    "nav-findings":       "Hallazgos",
    "nav-pipeline":       "Pipeline",
    "nav-reports":        "Reportes",
    "nav-settings":       "Configuración",
    "lbl-overview":       "Resumen",
    "lbl-last-scan":      "Último escaneo",
    "btn-export":         "Exportar",
    "btn-run-scan":       "Ejecutar escaneo",
    "live-exposure":      "En vivo · Exposición activa",
    "sev-critical":       "Crítico",
    "sev-high":           "Alto",
    "sev-medium":         "Medio",
    "sev-low":            "Bajo",
    "kpi-sla-breaches":   "Brechas SLA",
    "kpi-live":           "↑ en vivo",
    "kpi-mttr":           "MTTR · críticos",
    "kpi-mttr-foot":      "Objetivo 3.0d · mejorando",
    "ai-remediation":     "Remediación IA",
    "remediation-engine": "Motor de remediación",
    "local-model-ready":  "Modelo local listo",
    "ollama-offline":     "Ollama sin conexión",
    "patches-today":      "Parches hoy",
    "accept-rate":        "Tasa de aceptación",
    "view-findings":      "Hallazgos",
    "view-report":        "Reporte",
    "filter-all":         "Todos",
    "filter-breach":      "Vencidos",
    "btn-fix":            "Fix",
    "btn-risk":           "Riesgo",
    "btn-fp":             "FP",
    "btn-history":        "Historial",
    "modal-footer-pr":    "Convierte esta remediación en una propuesta de revisión en GitHub.",
    "scanning-adapters":  "Escaneando · 3 de 4 adaptores",
    "ai-adapter-offline": "Escaneando · adaptador IA sin conexión",
    "report-total-lbl":   "Total hallazgos",
    "report-crithigh-lbl":"Critical + High",
    "report-overdue-lbl": "SLA vencidos",
    "report-sev-lbl":     "Por Severidad",
    "report-status-lbl":  "Por Estado",
    "report-rules-lbl":   "Top Reglas",
    "btn-export-pdf":     "Exportar como PDF",
  },
  en: {
    "new-project":        "New Project",
    "scan-project":       "▶ Scan Project",
    "projects":           "Projects",
    "registered-projects":"registered projects",
    "findings-loaded":    "findings loaded",
    "refresh":            "Refresh",
    "not-executed":       "Not executed",
    "last-scan":          "Last scan",
    "open-findings":      "Open Findings",
    "convert-pr":         "Open Pull Request",
    "delete-branch":      "Delete Branch",
    "suggested-remediation": "Suggested Remediation",
    "vulnerable-code":    "Vulnerable Code",
    "proposed-code":      "Proposed Secure Code",
    "upload-zip":         "Upload ZIP",
    "clone-repo":         "Clone Repo",
    "project-name":       "Project name",
    "clone-scan":         "Clone and Scan",
    "create-from-zip":    "Create from ZIP",
    "select-project":     "Select a project",
    "findings-appear":    "Findings will appear here.",
    "no-findings":        "No findings detected for this project.",
    "findings-across":    "findings across",
    "nav-overview":       "Overview",
    "nav-findings":       "Findings",
    "nav-pipeline":       "Pipeline",
    "nav-reports":        "Reports",
    "nav-settings":       "Settings",
    "lbl-overview":       "Overview",
    "lbl-last-scan":      "Last scan",
    "btn-export":         "Export",
    "btn-run-scan":       "Run new scan",
    "live-exposure":      "Live · Active exposure",
    "sev-critical":       "Critical",
    "sev-high":           "High",
    "sev-medium":         "Medium",
    "sev-low":            "Low",
    "kpi-sla-breaches":   "SLA breaches",
    "kpi-live":           "↑ live",
    "kpi-mttr":           "MTTR · critical",
    "kpi-mttr-foot":      "Target 3.0d · trending fast",
    "ai-remediation":     "AI remediation",
    "remediation-engine": "Remediation engine",
    "local-model-ready":  "Local model ready",
    "ollama-offline":     "Ollama offline",
    "patches-today":      "Patches today",
    "accept-rate":        "Accept rate",
    "view-findings":      "Findings",
    "view-report":        "Report",
    "filter-all":         "All",
    "filter-breach":      "Breach",
    "btn-fix":            "Fix",
    "btn-risk":           "Risk",
    "btn-fp":             "FP",
    "btn-history":        "History",
    "modal-footer-pr":    "Convert this remediation into a GitHub pull request.",
    "scanning-adapters":  "Scanning · 3 of 4 adapters",
    "ai-adapter-offline": "Scanning · AI adapter offline",
    "report-total-lbl":   "Total findings",
    "report-crithigh-lbl":"Critical + High",
    "report-overdue-lbl": "Overdue SLA",
    "report-sev-lbl":     "By Severity",
    "report-status-lbl":  "By Status",
    "report-rules-lbl":   "Top Rules",
    "btn-export-pdf":     "Export as PDF",
  },
};

export let currentLang = "en";
export function setLang(lang) { currentLang = lang; }
export function t(key) { return i18n[currentLang]?.[key] ?? i18n.es[key] ?? key; }
export function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const v = t(el.dataset.i18n);
    if (v) el.textContent = v;
  });
}

// ── Bandit descriptions (ES) ─────────────────────────────────────────────
export const BANDIT_ES = {
  B101:"Uso de assert detectado — no usar en producción para validaciones",
  B102:"Uso de exec() detectado — posible ejecución de código arbitrario",
  B103:"Configuración de máscara de permisos de archivo insegura",
  B104:"Binding a todas las interfaces de red (0.0.0.0)",
  B105:"Posible contraseña en texto plano detectada en el código",
  B106:"Posible contraseña como argumento de función",
  B107:"Posible contraseña en argumento de URL",
  B108:"Ubicación de archivo temporal probablemente insegura",
  B110:"Try-except-pass detectado — puede ocultar errores silenciosamente",
  B201:"Aplicación Flask ejecutándose con debug=True en producción",
  B301:"Uso de pickle — riesgo de deserialización arbitraria",
  B303:"Uso de hash débil (MD2/MD4/MD5/SHA1) para seguridad",
  B304:"Uso de cifrado débil (RC2/RC4/DES/Blowfish)",
  B305:"Modo de cifrado ECB detectado — inseguro, sin IV",
  B307:"Uso de eval() — posible ejecución de código no confiable",
  B311:"Generador de números aleatorios estándar — no apto para criptografía",
  B322:"Uso de input() en Python 2 — puede ejecutar código arbitrario",
  B323:"Uso de unverified_context — verificación SSL desactivada",
  B324:"Uso de función hash débil para seguridad (usedforsecurity=False recomendado)",
  B401:"Importación de telnetlib — protocolo inseguro (sin cifrado)",
  B403:"Importación de pickle — posible vulnerabilidad de deserialización",
  B404:"Importación de subprocess — revisar argumentos para evitar inyección",
  B501:"Llamada a requests sin verificación SSL (verify=False)",
  B505:"Clave RSA menor a 2048 bits — insuficiente para seguridad moderna",
  B506:"yaml.load() sin Loader seguro — posible ejecución de código",
  B601:"Posible inyección de comandos vía formato de cadena en shell",
  B602:"Llamada a subprocess con shell=True — riesgo de inyección de comandos",
  B603:"subprocess sin shell=True — verificar que los argumentos sean de confianza",
  B604:"Función con shell=True detectada — posible inyección de comandos",
  B607:"Inicio de proceso con ruta parcial — susceptible a ataques PATH",
  B608:"Posible inyección SQL mediante concatenación de cadenas en consulta",
  B701:"Uso de Jinja2 con autoescape desactivado — riesgo de XSS",
  B703:"Uso de mark_safe en Django — posible XSS",
};

// ── SVG icon constants ──────────────────────────────────────────────────
export const IC_SPARKLE = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>`;
export const IC_WARN  = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>`;
export const IC_CROSS = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>`;
export const IC_CLOCK = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`;

// ── DOM helpers ─────────────────────────────────────────────────────────
let _feedbackTimeout = null;

export function showFeedback(message, tone = "info") {
  const feedback = document.getElementById("feedback");
  if (!feedback) return;
  feedback.className = { info: "fb-info", success: "fb-success", error: "fb-error", warning: "fb-warning" }[tone] || "fb-info";
  feedback.textContent = message;
  feedback.style.display = "block";
  window.clearTimeout(_feedbackTimeout);
  _feedbackTimeout = window.setTimeout(() => {
    feedback.style.display = "none";
    feedback.textContent = "";
  }, 10000);
}

export function ensureServerContext() {
  if (window.location.protocol === "file:") {
    showFeedback("Abre el dashboard desde http://127.0.0.1:8000 para ejecutar escaneos.", "error");
    return false;
  }
  return true;
}

export function escapeHtml(value) {
  const el = document.createElement("span");
  el.textContent = value == null ? "" : String(value);
  return el.innerHTML;
}

export function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

export function setWidth(id, pct) {
  const el = document.getElementById(id);
  if (el) el.style.width = `${Math.max(0, Math.min(100, pct))}%`;
}

// ── Severity helpers ────────────────────────────────────────────────────
export function severityKey(severity) {
  const v = String(severity || "").toUpperCase();
  if (v === "CRITICAL") return "critical";
  if (v === "HIGH")     return "high";
  if (v === "MEDIUM")   return "medium";
  if (v === "LOW")      return "low";
  return "low";
}

export function severityClass(severity) {
  return { critical: "c", high: "h", medium: "m", low: "l" }[severityKey(severity)];
}

export function sevStyle(severity) {
  const v = String(severity || "").toUpperCase();
  const map = { CRITICAL: "sev-critical", HIGH: "sev-high", MEDIUM: "sev-medium", LOW: "sev-low" };
  return map[v] || "sev-info";
}

// ── Display helpers ─────────────────────────────────────────────────────
export function fileLine(record) {
  return record.line_number || record.line || record.line_start || record.line_no || 1;
}

export function formatRelativeTime(value) {
  if (!value) return "discovered recently";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "discovered recently";
  const diff = Date.now() - date.getTime();
  const abs = Math.abs(diff);
  const mins = Math.round(abs / 60000);
  const hours = Math.round(abs / 3600000);
  const days = Math.round(abs / 86400000);
  if (mins < 60)  return `discovered ${Math.max(1, mins)}m ago`;
  if (hours < 48) return `discovered ${hours}h ago`;
  return `discovered ${days}d ago`;
}

export function formatShortDuration(ms) {
  const abs = Math.max(0, Math.abs(ms));
  const totalMinutes = Math.ceil(abs / 60000);
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;
  if (days > 0)  return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  if (hours > 0) return minutes > 0 ? `${hours}h ${minutes}min` : `${hours}h`;
  return `${Math.max(1, minutes)}min`;
}

export function techStyle(tech) {
  const v = String(tech || "").toLowerCase();
  if (v === "python")    return "background:#1a3a5c;color:#58a6ff;border:1px solid #1d4b7a;";
  if (v === "angular" || v === "typescript") return "background:#3a1a1a;color:#f85149;border:1px solid #5a2323;";
  if (v === "java")      return "background:#3a2e1a;color:#d29922;border:1px solid #5a471a;";
  return "background:var(--bg-hover);color:var(--muted);border:1px solid var(--border);";
}

export function lifecycleStyle(status) {
  const map = {
    open:           "background:rgba(47,129,247,.15);color:#6cb6ff;border:1px solid rgba(47,129,247,.35);",
    regression:     "background:rgba(248,81,73,.15);color:#ff7b72;border:1px solid rgba(248,81,73,.5);",
    fixed:          "background:rgba(63,185,80,.15);color:#56d364;border:1px solid rgba(63,185,80,.35);",
    accepted_risk:  "background:rgba(210,153,34,.1);color:#d29922;border:1px solid rgba(210,153,34,.3);",
    false_positive: "background:var(--bg-hover);color:var(--muted);border:1px solid var(--border);",
  };
  return map[String(status).toLowerCase()] || map.open;
}

export function shortPath(fullPath) {
  if (!fullPath) return "";
  return fullPath.replace(/.*\/repo\//, "").replace(/.*\/source\//, "");
}

export function cleanCodeFences(text) {
  if (!text) return "";
  return text.replace(/^```[\w]*\n?/, "").replace(/\n?```$/, "").trim();
}

export function formatApiError(detail, fallback) {
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  return detail.message || detail.technical_detail || fallback;
}

// ── Tool detection + badge ──────────────────────────────────────────────
export function detectTool(finding) {
  const ruleId = (finding.rule_id || "").toLowerCase();
  if (/^(python|web|java|typescript|javascript|cs|xml|kotlin|php|ruby):[a-z]\d{3,}/.test(ruleId)) return "sonarqube";
  if (ruleId.startsWith("python.lang") || ruleId.startsWith("python.flask") ||
      ruleId.startsWith("python.django") || ruleId.startsWith("gitlab.") ||
      ruleId.includes("semgrep") || ruleId.includes("/")) return "semgrep";
  if (/^b\d{3}$/.test(ruleId)) return "bandit";
  if (ruleId.startsWith("pylint") || ruleId.includes("pylint")) return "pylint";
  if (ruleId.startsWith("eslint") || ruleId.includes("eslint")) return "eslint";
  const scanTool = (finding.tool || "").toLowerCase();
  if (scanTool.includes("sonar")) return "sonarqube";
  if (scanTool.includes("bandit")) return "bandit";
  if (scanTool.includes("semgrep")) return "semgrep";
  if (scanTool.includes("eslint")) return "eslint";
  if (scanTool.includes("pylint")) return "pylint";
  return "unknown";
}

export function buildToolBadge(finding) {
  const tool = detectTool(finding);
  const badges = {
    sonarqube: { label: "SonarQube", color: "rgba(59,130,246,0.15)",  border: "rgba(59,130,246,0.4)",  text: "#60a5fa" },
    bandit:    { label: "Bandit",    color: "rgba(234,179,8,0.15)",   border: "rgba(234,179,8,0.4)",   text: "#d29922" },
    semgrep:   { label: "Semgrep",   color: "rgba(88,166,255,0.15)",  border: "rgba(88,166,255,0.4)",  text: "#58a6ff" },
    eslint:    { label: "ESLint",    color: "rgba(255,123,114,0.15)", border: "rgba(255,123,114,0.4)", text: "#ff7b72" },
    pylint:    { label: "Pylint",    color: "rgba(63,185,80,0.15)",   border: "rgba(63,185,80,0.4)",   text: "#3fb950" },
    unknown:   { label: "Scanner",   color: "rgba(110,118,129,0.15)", border: "rgba(110,118,129,0.4)", text: "#8b949e" },
  };
  const b = badges[tool] || badges.unknown;
  return `<span style="background:${b.color};border:1px solid ${b.border};color:${b.text};padding:1px 7px;border-radius:4px;font-size:11px;font-family:monospace;font-weight:700;white-space:nowrap;">${b.label}</span>`;
}
