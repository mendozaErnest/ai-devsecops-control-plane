// ── modal.js — all modal lifecycle, wizard, PR, audit ────────────────────────
import {
  t, escapeHtml, showFeedback, formatApiError, cleanCodeFences, shortPath,
  BANDIT_ES,
} from "/static/js/utils.js";
import {
  generateRemediation, getRemediationPr, createPR, deletePRBranch,
  getPRDiff, getSourceFile, getAuditHistory, postLifecycleAction,
  getProfiles, createProfile, getRemediationPreview,
} from "/static/js/api.js";
import { renderDiffView, renderGitHubDiff, renderPreviewDiff } from "/static/js/diff.js";

// ── DOM refs (modal-scoped) ──────────────────────────────────────────────────
const remediationModal    = document.getElementById("remediation-modal");
const remediationSubtitle = document.getElementById("remediation-subtitle");
const vulnerableCode      = document.getElementById("vulnerable-code");
const remediationContent  = document.getElementById("remediation-content");
const diffView            = document.getElementById("diff-view");
const closeRemediationButton = document.getElementById("close-remediation");
const createPrButton      = document.getElementById("btn-pr");
const prActionContainer   = document.getElementById("pr-action-container");
const branchConfirmModal  = document.getElementById("branch-confirm-modal");
const branchConfirmBranch = document.getElementById("branch-confirm-branch");
const branchConfirmClose  = document.getElementById("close-branch-confirm");
const branchConfirmCancel = document.getElementById("cancel-branch-delete");
const branchConfirmDelete = document.getElementById("confirm-branch-delete");
const reasonModal         = document.getElementById("reason-modal");
const reasonModalTitle    = document.getElementById("reason-modal-title");
const reasonModalDesc     = document.getElementById("reason-modal-desc");
const reasonInput         = document.getElementById("reason-input");
const confirmReasonBtn    = document.getElementById("confirm-reason-btn");
const closeReasonModalBtn = document.getElementById("close-reason-modal");
const auditModal          = document.getElementById("audit-modal");
const auditModalMeta      = document.getElementById("audit-modal-meta");
const auditEventsList     = document.getElementById("audit-events-list");
const closeAuditModalBtn  = document.getElementById("close-audit-modal");
const projectModal        = document.getElementById("project-modal");
const closeProjectModalButton = document.getElementById("close-project-modal");
const uploadProjectForm   = document.getElementById("upload-project-form");
const cloneProjectForm    = document.getElementById("clone-project-form");
const tabZip              = document.getElementById("tab-zip");
const tabClone            = document.getElementById("tab-clone");
const cloneGhBtn          = document.getElementById("clone-gh");
const cloneGlBtn          = document.getElementById("clone-gl");
const repoUrlInput        = document.getElementById("repo-url");
const panelZip            = document.getElementById("panel-zip");
const panelClone          = document.getElementById("panel-clone");
const wizardStep1         = document.getElementById("wizard-step-1");
const wizardStep2         = document.getElementById("wizard-step-2");
const profileCards        = document.getElementById("profile-cards");
const customPanel         = document.getElementById("custom-profile-panel");
const wizardNextBtn       = document.getElementById("wizard-next-btn");
const bcStep1             = document.getElementById("bc-step1");
const bcStep2             = document.getElementById("bc-step2");

// ── Module state ─────────────────────────────────────────────────────────────
let currentRemediationFindingId;
let currentPrBranch;
let _diffHunkInfo = null;
let _diffFileData = null;
let _usingGitHubDiff = false;
let reasonModalCallback = null;
let wizardProfiles = [];
let wizardSelectedProfileId = null;
// P1 fix: epoch counter — incremented every time a new finding modal is opened.
// All async callbacks capture their epoch at launch and abort if it no longer
// matches _modalEpoch, preventing stale results from a previous finding from
// overwriting the current one.
let _modalEpoch = 0;

// Callbacks wired by main.js after modules are loaded
export let onProjectCreated = null;

export function setOnProjectCreated(cb) { onProjectCreated = cb; }

// State getters needed by other modules
export function getCurrentRemediationFindingId() { return currentRemediationFindingId; }

// ── PR button helpers ─────────────────────────────────────────────────────────
function enforcePullRequestButtonRow() {
  createPrButton.style.display = "flex";
  createPrButton.style.flexDirection = "row";
  createPrButton.style.alignItems = "center";
  createPrButton.style.justifyContent = "center";
  createPrButton.style.gap = "8px";
  createPrButton.style.width = "fit-content";
  createPrButton.style.minWidth = "232px";
  createPrButton.style.whiteSpace = "nowrap";

  const icon = createPrButton.querySelector("svg");
  if (icon) {
    icon.style.display = "block";
    icon.style.flexShrink = "0";
    icon.style.minWidth = "14px";
  }

  const label = createPrButton.querySelector("[data-i18n='convert-pr']");
  if (label) {
    label.style.display = "inline";
    label.style.lineHeight = "1";
    label.style.whiteSpace = "nowrap";
  }
}

function resetPullRequestAction(hasRemediation = true) {
  prActionContainer.innerHTML = "";
  prActionContainer.appendChild(createPrButton);
  createPrButton.style.display = hasRemediation ? "flex" : "none";
  createPrButton.disabled = false;
  createPrButton.querySelector("[data-i18n='convert-pr']").textContent = t("convert-pr");
  createPrButton.style.opacity = "1";
  createPrButton.style.cursor = "pointer";
  enforcePullRequestButtonRow();
  if (!hasRemediation) createPrButton.style.display = "none";
}

// P3 fix: prType = "proposal" | "code_fix" | undefined
// Shows a yellow badge for proposals (no real code applied) and green for merged fixes.
function renderPullRequestSuccess(prUrl, prType) {
  prActionContainer.innerHTML = "";
  const wrap = document.createElement("div");
  wrap.style.cssText = "display:flex;align-items:center;gap:10px;flex-wrap:wrap;";

  const link = document.createElement("a");
  link.href = prUrl; link.target = "_blank"; link.rel = "noopener noreferrer";
  link.style.cssText = "color:var(--accent);font-size:.83rem;text-decoration:underline;";
  link.textContent = "🔗 Ver Pull Request en GitHub";

  // PR type badge: yellow = proposal-only (no code changed), green = real patch applied
  const typeBadge = document.createElement("span");
  if (prType === "proposal") {
    typeBadge.style.cssText =
      "padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;" +
      "background:rgba(234,179,8,.15);color:#eab308;border:1px solid rgba(234,179,8,.3);";
    typeBadge.textContent = "⚠ PR de propuesta";
    typeBadge.title = "Este PR no modifica código fuente. Contiene la propuesta de Ollama para revisión manual.";
  } else {
    typeBadge.style.cssText =
      "padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:700;" +
      "background:rgba(63,185,80,.12);color:#3fb950;border:1px solid rgba(63,185,80,.3);";
    typeBadge.textContent = "✓ Fix aplicado";
    typeBadge.title = "Este PR contiene el parche de seguridad aplicado al código fuente.";
  }

  const delBtn = document.createElement("button");
  delBtn.type = "button";
  delBtn.style.cssText =
    "padding:7px 14px;border-radius:6px;background:#5a1d1d;border:1px solid #8b2020;" +
    "color:#ff7b72;font-size:.8rem;font-weight:600;cursor:pointer;transition:background .15s;";
  delBtn.textContent = `🗑 ${t("delete-branch")}`;
  delBtn.addEventListener("click", () => deletePullRequestBranch(delBtn));

  wrap.append(link, typeBadge, delBtn);
  prActionContainer.appendChild(wrap);
}

function renderDiffStatus(message) {
  diffView.innerHTML = "";
  diffView.style.flexDirection = "column";

  const box = document.createElement("div");
  box.style.cssText =
    "display:flex;align-items:center;justify-content:center;height:100%;" +
    "color:#8b949e;font-size:.82rem;text-align:center;padding:24px;line-height:1.45;";
  box.textContent = message;
  diffView.appendChild(box);
}

async function renderGitHubPrDiff(findingId, epoch) {
  if (epoch !== undefined && epoch !== _modalEpoch) return false;

  _usingGitHubDiff = true;
  renderDiffStatus("Cargando diff real desde GitHub...");

  try {
    const diffData = await getPRDiff(findingId);
    if (epoch !== undefined && epoch !== _modalEpoch) return false;

    if (diffData && diffData.diff) {
      renderGitHubDiff(diffView, diffData.diff);
      return true;
    }

    renderDiffStatus(diffData?.message || "No se pudo cargar el diff real del PR en GitHub.");
  } catch (_) {
    if (epoch !== undefined && epoch !== _modalEpoch) return false;
    renderDiffStatus("No se pudo cargar el diff real del PR en GitHub.");
  }

  return false;
}

// ── Remediation modal ─────────────────────────────────────────────────────────
export function showRemediationModal(record, patch, selectedProject) {
  // P1 fix: advance epoch so any in-flight async operations from the PREVIOUS
  // finding become stale and self-abort before touching shared DOM or state.
  const epoch = ++_modalEpoch;
  const shouldCheckExistingPr = record.has_remediation && selectedProject?.source_type === "repo";

  // P1 fix: reset module-level state immediately — never let a previous
  // finding's data bleed into the new one even for a single frame.
  currentRemediationFindingId = record.id;
  currentPrBranch = undefined;
  _usingGitHubDiff = shouldCheckExistingPr;
  _diffFileData = null;
  _diffHunkInfo = null;

  // P1 fix: clear the diff panel immediately with a loading placeholder so
  // the old finding's content is never visible while the new one loads.
  diffView.innerHTML =
    '<div style="display:flex;align-items:center;justify-content:center;' +
    `height:100%;color:#484f58;font-size:.8rem;">${
      shouldCheckExistingPr ? "Cargando diff real de GitHub…" : "Cargando diff…"
    }</div>`;

  const ruleId = escapeHtml(record.rule_id || "UNKNOWN");
  const relPath = escapeHtml(shortPath(record.file_path || ""));
  remediationSubtitle.innerHTML =
    `<span style="display:inline-flex;align-items:center;gap:8px;">` +
    `<span style="padding:1px 7px;border-radius:4px;font-size:.7rem;font-weight:700;` +
    `background:rgba(47,129,247,.2);color:#6cb6ff;border:1px solid rgba(47,129,247,.4);">${ruleId}</span>` +
    `<span style="color:var(--muted);font-family:monospace;font-size:.78rem;">${relPath}</span>` +
    `</span>`;

  const cleanPatch = cleanCodeFences(patch || "No patch was returned.");
  vulnerableCode.textContent = record.code_snippet || "";
  remediationContent.textContent = cleanPatch;

  const detailPanel = document.getElementById("remediation-detail");
  const descEl = document.getElementById("remediation-description");
  const metaChips = document.getElementById("remediation-meta-chips");
  if (detailPanel && descEl && metaChips) {
    const descEn = record.description || record.rule_id || "";
    const ruleKey = (record.rule_id || "").replace(/[^A-Z0-9]/gi, "").toUpperCase();
    const descEs = BANDIT_ES[ruleKey] || descEn;
    let descShowingEs = false;

    function applyDesc() {
      descEl.textContent = descShowingEs ? descEs : descEn;
      const toggleBtn = document.getElementById("desc-lang-toggle");
      if (toggleBtn) {
        toggleBtn.textContent = descShowingEs ? "EN" : "ES";
        toggleBtn.title = descShowingEs ? "Ver en inglés" : "Ver en español";
        toggleBtn.style.color = "var(--t-dim)";
        toggleBtn.style.display = "";
      }
    }
    applyDesc();

    const toggleBtn = document.getElementById("desc-lang-toggle");
    if (toggleBtn) {
      toggleBtn.onclick = () => { descShowingEs = !descShowingEs; applyDesc(); };
      toggleBtn.style.display = "";
    }

    metaChips.innerHTML = "";
    const chipStyle = "display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:5px;font-size:.72rem;font-weight:600;";
    const sevColors = {
      CRITICAL: "background:rgba(239,68,68,.15);color:#ef4444;",
      HIGH:     "background:rgba(220,38,38,.13);color:#dc2626;",
      MEDIUM:   "background:rgba(234,179,8,.15);color:#eab308;",
      LOW:      "background:rgba(59,130,246,.13);color:#3b82f6;",
    };
    const sevCol = sevColors[String(record.severity || "").toUpperCase()] || sevColors.LOW;
    if (record.severity) {
      const s = document.createElement("span");
      s.style.cssText = chipStyle + sevCol;
      s.textContent = record.severity;
      metaChips.appendChild(s);
    }
    if (record.cvss) {
      const s = document.createElement("span");
      s.style.cssText = chipStyle + "background:rgba(255,255,255,.06);color:var(--t-dim);";
      s.textContent = `CVSS ${record.cvss}`;
      metaChips.appendChild(s);
    }
    if (record.cve_id) {
      const s = document.createElement("span");
      s.style.cssText = chipStyle + "background:rgba(47,129,247,.12);color:#6cb6ff;";
      s.textContent = record.cve_id;
      metaChips.appendChild(s);
    }
    const toolName = record.tool || selectedProject?.last_scan_tool || "";
    if (toolName) {
      const s = document.createElement("span");
      s.style.cssText = chipStyle + "background:rgba(255,255,255,.06);color:var(--t-dim);";
      s.textContent = toolName;
      metaChips.appendChild(s);
    }
    detailPanel.style.display = (record.description || record.severity) ? "" : "none";
  }

  // Fetch file context + exact preview in parallel (non-blocking).
  // P1 fix: capture epoch so this callback self-aborts if a newer finding
  // was opened while the fetch was in flight.
  // Fix 2: try renderPreviewDiff first (uses server-side build_safe_patched_content
  // so the diff matches exactly what the PR will commit); fall back to
  // renderDiffView if the preview endpoint is unavailable (no source file, etc.).
  (async (capturedEpoch) => {
    const hasRemediation = Boolean(record.has_remediation);
    const [fileResult, previewResult] = await Promise.allSettled([
      getSourceFile(record.id),
      hasRemediation ? getRemediationPreview(record.id) : Promise.resolve(null),
    ]);

    // Stale check: a newer finding has been opened — discard this result
    if (capturedEpoch !== _modalEpoch) return;

    _diffFileData = fileResult.status === "fulfilled" ? fileResult.value : null;
    _diffHunkInfo = null;

    if (!_usingGitHubDiff) {
      const preview = previewResult.status === "fulfilled" ? previewResult.value : null;
      if (preview?.original !== undefined && preview?.patched !== undefined) {
        renderPreviewDiff(diffView, preview.original, preview.patched);
      } else {
        renderDiffView(diffView, record.code_snippet || "", cleanPatch, _diffFileData);
      }
    }
  })(epoch);

  const showPrBtn = shouldCheckExistingPr;
  resetPullRequestAction(showPrBtn);
  remediationModal.style.display = "flex";
  document.body.style.overflow = "hidden";

  if (shouldCheckExistingPr) {
    checkExistingPR(record, cleanPatch, epoch);
  }
}

// P1 fix: epoch param — each call captures the epoch at open time.
// Any await that returns after a newer finding is opened is silently discarded.
async function checkExistingPR(record, cleanPatch, epoch) {
  const findingId = record.id;
  try {
    const data = await getRemediationPr(findingId);
    if (epoch !== _modalEpoch) return; // stale — newer finding opened
    if (!data || !data.pr_url) {
      _usingGitHubDiff = false;
      renderDiffView(diffView, record.code_snippet || "", cleanPatch, _diffFileData);
      return;
    }

    currentPrBranch = data.branch;
    renderPullRequestSuccess(data.pr_url, data.pr_type);
    await renderGitHubPrDiff(findingId, epoch);
  } catch (_) {
    if (epoch !== _modalEpoch) return;
    _usingGitHubDiff = false;
    renderDiffView(diffView, record.code_snippet || "", cleanPatch, _diffFileData);
  }
}

export function hideRemediationModal() {
  // P1 fix: advance epoch so any still-running async fetch for the closing
  // modal self-aborts and doesn't write to the (now empty) panel.
  _modalEpoch++;

  remediationModal.style.display = "none";
  document.body.style.overflow = "";
  diffView.innerHTML = "";
  diffView.style.flexDirection = "";
  vulnerableCode.textContent = "";
  remediationContent.textContent = "";
  const det = document.getElementById("remediation-detail");
  if (det) det.style.display = "none";
  currentRemediationFindingId = undefined;
  currentPrBranch = undefined;
  _diffHunkInfo = null;
  _diffFileData = null;
  _usingGitHubDiff = false;
}

// ── PR creation ───────────────────────────────────────────────────────────────
export async function createPullRequest() {
  if (!currentRemediationFindingId) {
    showFeedback("Primero genera una remediación para este hallazgo.", "error");
    return;
  }
  createPrButton.disabled = true;
  createPrButton.style.opacity = ".5";
  createPrButton.style.cursor = "not-allowed";
  createPrButton.querySelector("[data-i18n='convert-pr']").textContent = "⏳ Creando PR…";
  enforcePullRequestButtonRow();

  try {
    const epoch = _modalEpoch;
    const result = await createPR(currentRemediationFindingId);
    currentPrBranch = result.branch;
    // P3: pass pr_type so the badge shows ⚠ PR de propuesta vs ✓ Fix aplicado
    renderPullRequestSuccess(result.pr_url, result.pr_type);
    renderGitHubPrDiff(currentRemediationFindingId, epoch);
    if (result.warning) {
      showFeedback(result.warning, "warning");
    } else if (result.pr_type === "proposal") {
      showFeedback(
        "PR de propuesta creado — el parche requiere revisión manual antes de aplicarse.",
        "warning"
      );
    } else {
      const isCached = result.cached === true;
      showFeedback(
        isCached
          ? "PR existente recuperado — no se creó uno nuevo."
          : "Pull Request creado correctamente.",
        isCached ? "info" : "success"
      );
    }
  } catch (error) {
    createPrButton.disabled = false;
    createPrButton.style.opacity = "1";
    createPrButton.style.cursor = "pointer";
    createPrButton.querySelector("[data-i18n='convert-pr']").textContent = t("convert-pr");
    enforcePullRequestButtonRow();
    const prev = prActionContainer.querySelector("p");
    if (prev) prev.remove();
    const errP = document.createElement("p");
    errP.style.cssText = "color:var(--crit);font-size:.8rem;margin-top:6px;";
    errP.textContent = formatApiError(error.detail, error.message || "Error al crear el PR.");
    prActionContainer.appendChild(errP);
  }
}

function confirmBranchDeletion(branchName) {
  if (!branchConfirmModal) return Promise.resolve(false);
  branchConfirmBranch.textContent = branchName || "security-fix-*";
  branchConfirmModal.style.display = "flex";

  return new Promise((resolve) => {
    const close = (confirmed) => {
      branchConfirmModal.style.display = "none";
      branchConfirmClose.removeEventListener("click", onCancel);
      branchConfirmCancel.removeEventListener("click", onCancel);
      branchConfirmDelete.removeEventListener("click", onConfirm);
      branchConfirmModal.removeEventListener("click", onBackdrop);
      window.removeEventListener("keydown", onKey);
      resolve(confirmed);
    };
    const onCancel = () => close(false);
    const onConfirm = () => close(true);
    const onBackdrop = (e) => { if (e.target === branchConfirmModal) close(false); };
    const onKey = (e) => { if (e.key === "Escape") close(false); };

    branchConfirmClose.addEventListener("click", onCancel);
    branchConfirmCancel.addEventListener("click", onCancel);
    branchConfirmDelete.addEventListener("click", onConfirm);
    branchConfirmModal.addEventListener("click", onBackdrop);
    window.addEventListener("keydown", onKey);
  });
}

async function deletePullRequestBranch(button) {
  if (!currentRemediationFindingId) {
    showFeedback("No hay rama asociada al hallazgo actual.", "error");
    return;
  }
  const confirmed = await confirmBranchDeletion(
    currentPrBranch || `security-fix-${currentRemediationFindingId}`
  );
  if (!confirmed) return;

  const orig = button.textContent;
  button.disabled = true;
  button.textContent = "⏳ Eliminando…";

  try {
    const result = await deletePRBranch(currentRemediationFindingId);
    currentPrBranch = undefined;
    resetPullRequestAction(true);
    showFeedback(
      result.pr_closed
        ? "Pull Request cerrado, rama eliminada y estado local limpiado."
        : "Rama eliminada y estado local limpiado.",
      "success"
    );
  } catch (error) {
    button.disabled = false;
    button.textContent = orig;
    showFeedback(
      `No se pudo eliminar la rama: ${formatApiError(error.detail, error.message)}`,
      "error"
    );
  }
}

// ── Reason modal ──────────────────────────────────────────────────────────────
export function openReasonModal(title, description, onConfirm) {
  reasonModalTitle.textContent = title;
  reasonModalDesc.textContent = description;
  reasonInput.value = "";
  reasonModalCallback = onConfirm;
  reasonModal.style.display = "flex";
  reasonInput.focus();
}

export function closeReasonModal() {
  reasonModal.style.display = "none";
  reasonModalCallback = null;
}

// ── Audit modal ───────────────────────────────────────────────────────────────
export async function openAuditModal(record) {
  auditModalMeta.textContent = `Finding ${String(record.id).slice(0, 8)} — ${record.rule_id || ""}`;
  auditEventsList.innerHTML = `<p style="color:var(--muted);font-size:.83rem;">Cargando historial…</p>`;
  auditModal.style.display = "flex";

  try {
    const data = await getAuditHistory(record.id);
    auditEventsList.innerHTML = "";

    const meta = document.createElement("p");
    meta.style.cssText = "font-size:.82rem;color:var(--text);margin-bottom:4px;";
    meta.innerHTML =
      `Estado: <strong style="color:#6cb6ff;">${data.current_status}</strong>` +
      ` &nbsp;·&nbsp; Regresiones: <strong style="color:#ff7b72;">${data.regression_count}</strong>`;
    auditEventsList.appendChild(meta);

    if (data.events.length === 0) {
      const empty = document.createElement("p");
      empty.style.cssText = "font-size:.82rem;color:var(--muted);";
      empty.textContent = "Sin eventos de auditoría registrados.";
      auditEventsList.appendChild(empty);
      return;
    }

    const label = {
      regression: "Regresión detectada",
      accept_risk: "Riesgo aceptado",
      false_positive: "Falso positivo",
      status_change: "Cambio de estado",
    };

    data.events.forEach((evt) => {
      const card = document.createElement("div");
      card.style.cssText =
        "background:var(--bg-hover);border:1px solid var(--border);" +
        "border-radius:6px;padding:10px 14px;font-size:.8rem;";
      card.innerHTML = `
        <div style="display:flex;justify-content:space-between;gap:8px;margin-bottom:4px;">
          <span style="font-weight:700;color:var(--text);">${label[evt.event_type] || evt.event_type}</span>
          <span style="color:var(--muted);font-size:.7rem;">${new Date(evt.created_at).toLocaleString()}</span>
        </div>
        <div style="color:var(--muted);">
          <code style="font-size:.72rem;">${evt.from_status}</code>
          <span style="margin:0 4px;"> → </span>
          <code style="font-size:.72rem;">${evt.to_status}</code>
        </div>
        ${evt.reason ? `<p style="margin-top:6px;color:var(--muted);font-style:italic;font-size:.78rem;">"${escapeHtml(evt.reason)}"</p>` : ""}
      `;
      auditEventsList.appendChild(card);
    });
  } catch (error) {
    auditEventsList.innerHTML =
      `<p style="color:var(--crit);font-size:.83rem;">Error al cargar historial: ${error.message}</p>`;
  }
}

export function closeAuditModal() { auditModal.style.display = "none"; }

// ── Project modal + wizard ────────────────────────────────────────────────────
export async function loadWizardProfiles() {
  try {
    wizardProfiles = await getProfiles();
  } catch { wizardProfiles = []; }
  renderProfileCards();
}

function renderProfileCards() {
  profileCards.innerHTML = "";

  const PROFILE_META = {
    "Python SAST": {
      icon: `<svg width="36" height="36" viewBox="0 0 36 36" fill="none"><rect width="36" height="36" rx="8" fill="#1a3a5c"/><text x="18" y="25" font-family="monospace" font-size="15" font-weight="800" fill="#58a6ff" text-anchor="middle">Py</text></svg>`,
      desc: "Bandit + Semgrep — detección de inyecciones, secrets y código inseguro",
      badge: "Bandit + Semgrep", badgeBg: "rgba(88,166,255,.15)", badgeColor: "#58a6ff",
    },
    "Angular SAST": {
      icon: `<svg width="36" height="36" viewBox="0 0 36 36" fill="none"><rect width="36" height="36" rx="8" fill="#3a1a1a"/><polygon points="18,5 30,10 27,26 18,31 9,26 6,10" fill="#dd0031" opacity="0.85"/><text x="18" y="24" font-family="sans-serif" font-size="13" font-weight="800" fill="white" text-anchor="middle">A</text></svg>`,
      desc: "Semgrep para XSS, bindings inseguros y secrets en TypeScript",
      badge: "Semgrep", badgeBg: "rgba(248,81,73,.15)", badgeColor: "#ff7b72",
    },
    "Java SAST": {
      icon: `<svg width="36" height="36" viewBox="0 0 36 36" fill="none"><rect width="36" height="36" rx="8" fill="#3a2e1a"/><text x="18" y="24" font-family="Geist Mono, monospace" font-size="13" font-weight="800" fill="#d29922" text-anchor="middle">Jv</text></svg>`,
      desc: "Semgrep — SQL injection, crypto débil y configuración TLS insegura",
      badge: "Semgrep", badgeBg: "rgba(210,153,34,.15)", badgeColor: "#d29922",
    },
    "Full Scan": {
      icon: `<svg width="36" height="36" viewBox="0 0 36 36" fill="none"><rect width="36" height="36" rx="8" fill="#1a3a2e"/><path d="M18 5L28 10v10c0 7-5.5 11-10 12-4.5-1-10-5-10-12V10L18 5z" fill="#3fb950" opacity="0.25" stroke="#3fb950" stroke-width="1.5"/><path d="M13 18l3.5 3.5L23 14" stroke="#3fb950" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
      desc: "SAST completo + DAST y Quality cuando los adapters estén instalados",
      badge: "SAST + SCA", badgeBg: "rgba(63,185,80,.15)", badgeColor: "#3fb950",
    },
    "Angular + Quality": {
      icon: `<svg width="36" height="36" viewBox="0 0 36 36" fill="none"><rect width="36" height="36" rx="8" fill="#3a1a2e"/><polygon points="18,5 30,10 27,26 18,31 9,26 6,10" fill="#dd0031" opacity="0.7"/><text x="18" y="23" font-family="sans-serif" font-size="11" font-weight="800" fill="white" text-anchor="middle">A★</text></svg>`,
      desc: "Semgrep + análisis de calidad de código Angular/TypeScript",
      badge: "Semgrep + Quality", badgeBg: "rgba(248,81,73,.15)", badgeColor: "#ff7b72",
    },
  };

  function inferProfileMeta(profile) {
    if (PROFILE_META[profile.name]) return PROFILE_META[profile.name];

    const name = String(profile.name || "").toLowerCase();
    const description = String(profile.description || "").toLowerCase();
    const text = `${name} ${description}`;

    if (text.includes("angular") || text.includes("typescript")) {
      return {
        ...PROFILE_META["Angular SAST"],
        desc: profile.description || PROFILE_META["Angular SAST"].desc,
        badge: profile.sast_tools || PROFILE_META["Angular SAST"].badge,
      };
    }
    if (text.includes("java")) {
      return {
        ...PROFILE_META["Java SAST"],
        desc: profile.description || PROFILE_META["Java SAST"].desc,
        badge: profile.sast_tools || PROFILE_META["Java SAST"].badge,
      };
    }
    if (text.includes("python")) {
      return {
        ...PROFILE_META["Python SAST"],
        desc: profile.description || PROFILE_META["Python SAST"].desc,
        badge: profile.sast_tools || PROFILE_META["Python SAST"].badge,
      };
    }
    if (text.includes("full")) {
      return {
        ...PROFILE_META["Full Scan"],
        desc: profile.description || PROFILE_META["Full Scan"].desc,
        badge: profile.sast_tools || PROFILE_META["Full Scan"].badge,
      };
    }

    return {
      icon: `<svg width="36" height="36" viewBox="0 0 36 36" fill="none"><rect width="36" height="36" rx="8" fill="var(--bg-hover)"/><circle cx="18" cy="18" r="3" fill="var(--muted)"/><path d="M18 8v4M18 24v4M8 18h4M24 18h4M11.5 11.5l2.8 2.8M21.7 21.7l2.8 2.8M11.5 24.5l2.8-2.8M21.7 14.3l2.8-2.8" stroke="var(--muted)" stroke-width="1.8" stroke-linecap="round"/></svg>`,
      desc: profile.description || profile.sast_tools || "SAST",
      badge: profile.sast_tools || "SAST",
      badgeBg: "var(--bg-hover)",
      badgeColor: "var(--muted)",
    };
  }

  const profileOrder = {
    "Python SAST": 1,
    "Angular SAST": 2,
    "Java SAST": 3,
    "Full Scan": 4,
    "Angular + Quality": 5,
  };

  const profileList = wizardProfiles.length
    ? wizardProfiles
    : [
        { id: null, name: "Python SAST" }, { id: null, name: "Angular SAST" },
        { id: null, name: "Java SAST" },   { id: null, name: "Full Scan" },
      ];

  [...profileList]
    .sort((a, b) => {
      const aOrder = profileOrder[a.name] || 100;
      const bOrder = profileOrder[b.name] || 100;
      if (aOrder !== bOrder) return aOrder - bOrder;
      return String(a.name || "").localeCompare(String(b.name || ""));
    })
    .forEach((p) => {
      const meta = inferProfileMeta(p);
      const isSelected = wizardSelectedProfileId === p.id;
      const card = document.createElement("button");
      card.type = "button";
      card.className = "profile-card" + (isSelected ? " profile-card-active" : "");
      card.dataset.profileId = p.id ?? "";
      card.style.cssText =
        `text-align:left;padding:14px;border-radius:8px;border:2px solid ${isSelected ? "var(--accent)" : "var(--border)"};` +
        `background:${isSelected ? "rgba(47,129,247,.12)" : "var(--bg-surface)"};cursor:pointer;` +
        "transition:border .15s,background .15s;min-height:135px;display:flex;flex-direction:column;gap:7px;";
      card.innerHTML = `
        ${meta.icon}
        <p style="font-size:.82rem;font-weight:700;color:var(--text);margin:0;">${escapeHtml(p.name)}</p>
        <p style="font-size:.72rem;color:var(--muted);line-height:1.4;flex:1;">${escapeHtml(meta.desc)}</p>
        <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:.67rem;font-weight:700;background:${meta.badgeBg};color:${meta.badgeColor};">${escapeHtml(meta.badge)}</span>`;
      card.addEventListener("click", () => {
        wizardSelectedProfileId = p.id;
        customPanel.style.display = "none";
        renderProfileCards();
      });
      profileCards.appendChild(card);
    });

  const isCustom = wizardSelectedProfileId === "custom";
  const customCard = document.createElement("button");
  customCard.type = "button";
  customCard.className = "profile-card" + (isCustom ? " profile-card-active" : "");
  customCard.style.cssText =
    `text-align:left;padding:14px;border-radius:8px;border:2px solid ${isCustom ? "var(--accent)" : "var(--border)"};` +
    `background:${isCustom ? "rgba(47,129,247,.12)" : "var(--bg-surface)"};cursor:pointer;` +
    "transition:border .15s,background .15s;min-height:135px;display:flex;flex-direction:column;gap:7px;";
  customCard.innerHTML = `
    <svg width="36" height="36" viewBox="0 0 36 36" fill="none"><rect width="36" height="36" rx="8" fill="var(--bg-hover)"/><circle cx="18" cy="18" r="3" fill="var(--muted)"/><path d="M18 8v4M18 24v4M8 18h4M24 18h4M11.5 11.5l2.8 2.8M21.7 21.7l2.8 2.8M11.5 24.5l2.8-2.8M21.7 14.3l2.8-2.8" stroke="var(--muted)" stroke-width="1.8" stroke-linecap="round"/></svg>
    <p style="font-size:.82rem;font-weight:700;color:var(--text);margin:0;">Personalizado</p>
    <p style="font-size:.72rem;color:var(--muted);line-height:1.4;flex:1;">Configura herramientas SAST, DAST y Quality manualmente</p>
    <span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:.67rem;font-weight:700;background:var(--bg-hover);color:var(--muted);">Manual</span>`;
  customCard.addEventListener("click", () => {
    wizardSelectedProfileId = "custom";
    customPanel.style.display = "";
    renderProfileCards();
  });
  profileCards.appendChild(customCard);
}

export function setModalTab(tab) {
  const isZip = tab === "zip";
  tabZip.className   = "tab-btn " + (isZip ? "tab-active" : "tab-inactive");
  tabClone.className = "tab-btn " + (isZip ? "tab-inactive" : "tab-active");
  panelZip.className   = "form-panel " + (isZip ? "visible-panel" : "hidden-panel");
  panelClone.className = "form-panel " + (isZip ? "hidden-panel" : "visible-panel");
}

export function setWizardStep(step) {
  const onStep1 = step === 1;
  wizardStep1.style.display = onStep1 ? "" : "none";
  wizardStep2.style.display = onStep1 ? "none" : "";
  bcStep1.style.color = onStep1 ? "var(--accent)" : "var(--muted)";
  bcStep2.style.color = onStep1 ? "var(--muted)" : "var(--accent)";
  if (!onStep1) setModalTab("zip");
}

function resolvedProfileId() {
  if (wizardSelectedProfileId === "custom" || wizardSelectedProfileId === null) return null;
  return wizardSelectedProfileId;
}

function qualityToolForTechnology(technology) {
  const selectedQualityTool = document.getElementById("custom-quality-tool")?.value || "auto";
  if (selectedQualityTool === "sonarqube") return "sonarqube";
  const normalized = String(technology || "").trim().toLowerCase();
  if (normalized === "python") return "pylint";
  if (normalized === "angular" || normalized === "typescript") return "eslint";
  return null;
}

function sastToolsForTechnology(technology, selectedTools) {
  const normalized = String(technology || "").trim().toLowerCase();
  if (normalized !== "python" && selectedTools === "bandit") return "semgrep";
  return selectedTools;
}

async function resolvedProfileIdForTechnology(technology) {
  if (wizardSelectedProfileId !== "custom") return resolvedProfileId();

  const selectedSastTools = document.querySelector('input[name="custom-sast-tools"]:checked')?.value || "semgrep";
  const sastTools = sastToolsForTechnology(technology, selectedSastTools);
  const wantsQuality = document.getElementById("custom-quality-enabled")?.checked || false;
  const qualityTool = wantsQuality ? qualityToolForTechnology(technology) : null;

  if (wantsQuality && !qualityTool) {
    throw new Error("Code Quality por ahora está disponible para Python y Angular/TypeScript.");
  }

  const payload = {
    name: `Custom ${String(technology || "Project").toUpperCase()} ${wantsQuality ? "SAST + Quality" : "SAST"}`,
    description: wantsQuality
      ? "Perfil personalizado creado desde el dashboard con SAST y Quality."
      : "Perfil personalizado creado desde el dashboard con SAST.",
    sast_enabled: true,
    sast_tools: sastTools,
    dast_enabled: false,
    quality_enabled: Boolean(qualityTool),
    quality_tool: qualityTool,
  };

  const data = await createProfile(payload);
  wizardProfiles.push(data);
  return data.id;
}

export function showProjectModal() {
  if (wizardProfiles.length === 0) loadWizardProfiles();
  if (wizardSelectedProfileId === null && wizardProfiles.length > 0) {
    wizardSelectedProfileId = wizardProfiles[0].id;
    renderProfileCards();
  }
  projectModal.style.display = "flex";
  setWizardStep(1);
}

export function hideProjectModal() {
  projectModal.style.display = "none";
  wizardSelectedProfileId = null;
}

export function setCloneSource(source) {
  cloneGhBtn.className = "tab-btn " + (source === "gh" ? "tab-active" : "tab-inactive");
  cloneGlBtn.className = "tab-btn " + (source === "gl" ? "tab-active" : "tab-inactive");
  repoUrlInput.placeholder = source === "gh"
    ? "https://github.com/usuario/repo.git"
    : "https://gitlab.com/usuario/repo.git";
}

// ── ZIP upload ────────────────────────────────────────────────────────────────
export async function uploadZipProject(event) {
  event.preventDefault();
  const fileInput = document.getElementById("zip-file");
  if (!fileInput.files.length) { showFeedback("Selecciona un archivo ZIP.", "error"); return; }

  const btn = uploadProjectForm.querySelector("button");
  const orig = btn.textContent;
  btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Cargando…`;

  try {
    const technology = document.getElementById("zip-technology").value;
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("name", document.getElementById("zip-name").value);
    formData.append("technology", technology);
    const pid = await resolvedProfileIdForTechnology(technology);
    if (pid !== null) formData.append("scan_profile_id", pid);

    const { uploadZip } = await import("/static/js/api.js");
    const result = await uploadZip(formData);
    hideProjectModal();
    uploadProjectForm.reset();
    if (onProjectCreated) await onProjectCreated(result.project);
    showFeedback("Proyecto ZIP creado y escaneado.", "success");
  } catch (error) {
    showFeedback(
      `No se pudo crear el proyecto: ${formatApiError(error.detail, error.message)}`,
      "error"
    );
  } finally {
    btn.disabled = false; btn.textContent = orig;
  }
}

// ── Repo clone ────────────────────────────────────────────────────────────────
export async function cloneRepoProject(event) {
  event.preventDefault();
  const payload = {
    name:      document.getElementById("repo-name").value,
    repo_url:  document.getElementById("repo-url").value,
    technology: document.getElementById("repo-technology").value,
  };
  if (!payload.name.trim() || !payload.repo_url.trim()) {
    showFeedback("Nombre y URL del repositorio son obligatorios.", "error"); return;
  }
  const btn = cloneProjectForm.querySelector("button");
  const orig = btn.textContent;
  btn.disabled = true; btn.innerHTML = `<span class="spinner"></span> Clonando…`;

  try {
    payload.scan_profile_id = await resolvedProfileIdForTechnology(payload.technology);
    const { cloneRepo } = await import("/static/js/api.js");
    const result = await cloneRepo(payload);
    hideProjectModal();
    cloneProjectForm.reset();
    if (onProjectCreated) await onProjectCreated(result.project);
    showFeedback("Repositorio clonado y escaneado.", "success");
  } catch (error) {
    showFeedback(
      `No se pudo crear el proyecto: ${formatApiError(error.detail, error.message)}`,
      "error"
    );
  } finally {
    btn.disabled = false; btn.textContent = orig;
  }
}

// ── postLifecycle ─────────────────────────────────────────────────────────────
export async function postLifecycle(findingId, action, reason, onSuccess) {
  try {
    await postLifecycleAction(findingId, action, reason);
    showFeedback("Estado actualizado correctamente.", "success");
    if (onSuccess) await onSuccess();
  } catch (error) {
    showFeedback(`Error al actualizar estado: ${error.message}`, "error");
  }
}

// ── Event wiring (called once from main.js) ───────────────────────────────────
export function wireModalEvents(ctx) {
  // ctx: { loadFindings, selectedProjectFn }
  closeRemediationButton.addEventListener("click", hideRemediationModal);
  remediationModal.addEventListener("click", (e) => { if (e.target === remediationModal) hideRemediationModal(); });

  createPrButton.addEventListener("click", createPullRequest);

  closeProjectModalButton.addEventListener("click", hideProjectModal);
  projectModal.addEventListener("click", (e) => { if (e.target === projectModal) hideProjectModal(); });

  tabZip.addEventListener("click", () => setModalTab("zip"));
  tabClone.addEventListener("click", () => setModalTab("clone"));
  cloneGhBtn.addEventListener("click", () => setCloneSource("gh"));
  cloneGlBtn.addEventListener("click", () => setCloneSource("gl"));

  uploadProjectForm.addEventListener("submit", uploadZipProject);
  cloneProjectForm.addEventListener("submit", cloneRepoProject);

  wizardNextBtn.addEventListener("click", () => setWizardStep(2));
  document.getElementById("wizard-back-zip")?.addEventListener("click", () => setWizardStep(1));
  document.getElementById("wizard-back-clone")?.addEventListener("click", () => setWizardStep(1));

  closeReasonModalBtn.addEventListener("click", closeReasonModal);
  reasonModal.addEventListener("click", (e) => { if (e.target === reasonModal) closeReasonModal(); });
  confirmReasonBtn.addEventListener("click", async () => {
    const reason = reasonInput.value.trim();
    if (!reason) { reasonInput.style.borderColor = "var(--crit)"; reasonInput.focus(); return; }
    reasonInput.style.borderColor = "";
    const cb = reasonModalCallback;
    closeReasonModal();
    if (cb) await cb(reason);
  });

  closeAuditModalBtn.addEventListener("click", closeAuditModal);
  auditModal.addEventListener("click", (e) => { if (e.target === auditModal) closeAuditModal(); });
}
