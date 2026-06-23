// ── modal.js — all modal lifecycle, wizard, PR, audit ────────────────────────
import {
  t, escapeHtml, showFeedback, formatApiError, cleanCodeFences, shortPath,
  BANDIT_ES,
} from "/static/js/utils.js";
import {
  generateRemediation, getRemediationPr, createPR, deletePRBranch,
  getPRDiff, getSourceFile, getAuditHistory, postLifecycleAction,
  getProfiles, getProjects, assignProjectProfile, createProfile, getRemediationPreview,
} from "/static/js/api.js";
import { renderDiffView, renderGitHubDiff, renderPreviewDiff } from "/static/js/diff.js";
import {
  SCAN_SLOT_ORDER, TECHNOLOGY_ITEMS, SCANNER_ITEMS,
  addScannerToDraft, addTechnologyToDraft, applyValidation,
  createEmptyProfileBuilderState, findScanner, findTechnology,
  getAllSelectedScannerIds, getApiTechnologiesFromState, getPrimaryApiTechnology, loadSessionProfile,
  isProjectCompatibleWithProfile, profileToDraft,
  removeScannerFromDraft, removeTechnologyFromDraft, saveSessionProfile,
  toScanProfilePayload,
} from "/static/js/profile-builder-state.js";

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
const compatibleProjectsList = document.getElementById("compatible-projects-list");
const compatibleProjectsStatus = document.getElementById("compatible-projects-status");

// ── Module state ─────────────────────────────────────────────────────────────
let currentRemediationFindingId;
let currentPrBranch;
let _diffHunkInfo = null;
let _diffFileData = null;
let _usingGitHubDiff = false;
let reasonModalCallback = null;
let wizardProfiles = [];
let wizardSelectedProfileId = null;
let wizardProfileDraft = createEmptyProfileBuilderState();
// P1 fix: epoch counter — incremented every time a new finding modal is opened.
// All async callbacks capture their epoch at launch and abort if it no longer
// matches _modalEpoch, preventing stale results from a previous finding from
// overwriting the current one.
let _modalEpoch = 0;

// Callbacks wired by main.js after modules are loaded
export let onProjectCreated = null;
export let onExistingProjectSelected = null;

export function setOnProjectCreated(cb) { onProjectCreated = cb; }
export function setOnExistingProjectSelected(cb) { onExistingProjectSelected = cb; }

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

  // Do NOT clear the panel here — keep the preview visible while GitHub diff loads.
  // Only replace content when the real diff arrives (or if there's nothing yet).
  try {
    const diffData = await getPRDiff(findingId);
    if (epoch !== undefined && epoch !== _modalEpoch) return false;

    if (diffData && diffData.diff) {
      renderGitHubDiff(diffView, diffData.diff);
      return true;
    }

    // GitHub diff unavailable: preserve existing content (preview) if present,
    // otherwise show an error placeholder.
    if (!diffView.querySelector("table")) {
      renderDiffStatus(diffData?.message || "No se pudo cargar el diff real del PR en GitHub.");
    }
  } catch (_) {
    if (epoch !== undefined && epoch !== _modalEpoch) return false;
    if (!diffView.querySelector("table")) {
      renderDiffStatus("No se pudo cargar el diff real del PR en GitHub.");
    }
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
  // Always start with false; checkExistingPR sets it to true only when a PR
  // is confirmed, so the IIFE can always render the preview first.
  _usingGitHubDiff = false;
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
      if (previewResult.status === "rejected") {
        console.warn("[diff preview] rejected:", previewResult.reason);
      } else if (!preview?.original || !preview?.patched) {
        console.warn("[diff preview] unavailable — original:", preview?.original !== undefined, "patched:", preview?.patched !== undefined);
      }
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
      // No existing PR — the IIFE has already rendered (or will render) the preview.
      // Do NOT call renderDiffView here; that would overwrite a successful preview.
      _usingGitHubDiff = false;
      return;
    }

    // PR found: mark flag BEFORE awaiting so the IIFE skips rendering if it hasn't run yet.
    _usingGitHubDiff = true;
    currentPrBranch = data.branch;
    renderPullRequestSuccess(data.pr_url, data.pr_type);
    await renderGitHubPrDiff(findingId, epoch);
  } catch (err) {
    if (epoch !== _modalEpoch) return;
    console.warn("[checkExistingPR] error:", err);
    // Let the IIFE's preview stand; just ensure flag is consistent.
    _usingGitHubDiff = false;
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

  wizardProfileDraft = applyValidation(wizardProfileDraft);
  const selectedTechnologies = wizardProfileDraft.selectedTechnologies || [];
  const selectedScanners = wizardProfileDraft.selectedScanners || {};
  const savedProfile = wizardProfileDraft.savedSessionProfile;

  const palette = document.createElement("aside");
  palette.className = "builder-palette";
  palette.appendChild(renderPaletteSection("Tecnologias", TECHNOLOGY_ITEMS, "technology"));
  palette.appendChild(renderPaletteSection("Scanners", SCANNER_ITEMS, "scanner"));

  const dropzone = document.createElement("section");
  dropzone.className = "builder-dropzone";
  dropzone.innerHTML = `
    <div class="builder-technology-zone" data-drop-slot="technologies">
      <div class="builder-zone-head">
        <div>
          <p class="builder-zone-title">Tecnologias del proyecto</p>
          <p class="builder-zone-hint">Arrastra una o mas tecnologias</p>
        </div>
      </div>
      <div class="builder-selected-row" data-selected-row="technologies"></div>
    </div>
    <div class="builder-slots">
      ${SCAN_SLOT_ORDER.map((slot) => renderScannerSlotMarkup(slot)).join("")}
    </div>
    <div id="profile-builder-message" class="builder-message"></div>
    <div class="builder-session-row">
      <span>${savedProfile ? `Perfil en sesion: ${escapeHtml(savedProfile.name)}` : "El perfil valido se guardara para esta sesion."}</span>
      <label>
        <input id="builder-reuse-profile" type="checkbox" ${wizardProfileDraft.applySavedProfileToNextProjects ? "checked" : ""}>
        Reusar en proyectos siguientes
      </label>
    </div>`;

  profileCards.appendChild(palette);
  profileCards.appendChild(dropzone);

  renderSelectedPills("technologies", selectedTechnologies, "technology");
  SCAN_SLOT_ORDER.forEach((slot) => renderSelectedPills(slot, selectedScanners[slot] || [], "scanner"));
  SCAN_SLOT_ORDER.forEach((slot) => {
    const slotEl = profileCards.querySelector(`[data-drop-slot="${slot}"]`);
    slotEl?.classList.toggle("covered", (selectedScanners[slot] || []).length > 0);
  });
  wireProfileBuilderDnD();
  renderBuilderValidationMessage();
  updateWizardNextButton();
}

function renderPaletteSection(title, items, type) {
  const section = document.createElement("div");
  const titleEl = document.createElement("p");
  titleEl.className = "builder-section-title";
  titleEl.textContent = title;

  const list = document.createElement("div");
  list.className = "builder-pill-list";

  items.forEach((item) => {
    list.appendChild(renderDraggablePill(item, type));
  });

  section.appendChild(titleEl);
  section.appendChild(list);
  return section;
}

function renderDraggablePill(item, type) {
  const pill = document.createElement("button");
  pill.type = "button";
  pill.className = "builder-pill";
  pill.draggable = true;
  pill.dataset.dragType = type;
  pill.dataset.itemId = item.id;
  pill.title = type === "technology"
    ? `Agregar ${item.label} al perfil`
    : `Agregar ${item.label} al bloque ${slotLabel(item.slot)}`;
  pill.innerHTML = `
    <span class="builder-pill-icon">${escapeHtml(item.iconLabel || item.label.slice(0, 2))}</span>
    <span>${escapeHtml(item.label)}</span>`;
  pill.addEventListener("click", () => {
    replaceWizardProfileDraft(type === "technology"
      ? addTechnologyToDraft(wizardProfileDraft, item.id)
      : addScannerToDraft(wizardProfileDraft, item.id));
    renderProfileCards();
  });
  return pill;
}

function renderScannerSlotMarkup(slot) {
  return `
    <div class="builder-slot" data-drop-slot="${slot}">
      <div class="builder-zone-head">
        <div>
          <p class="builder-zone-title">${escapeHtml(slotLabel(slot))}</p>
          <p class="builder-zone-hint">${escapeHtml(slotHint(slot))}</p>
        </div>
      </div>
      <div class="builder-selected-row" data-selected-row="${slot}"></div>
    </div>`;
}

function renderSelectedPills(rowName, itemIds, type) {
  const row = profileCards.querySelector(`[data-selected-row="${rowName}"]`);
  if (!row) return;
  row.innerHTML = "";

  if (!itemIds.length) {
    const empty = document.createElement("span");
    empty.className = "builder-empty";
    empty.textContent = rowName === "technologies" ? "Suelta tecnologias aqui" : "Suelta scanners aqui";
    row.appendChild(empty);
    return;
  }

  itemIds.forEach((id) => {
    const item = type === "technology" ? findTechnology(id) : findScanner(id);
    if (!item) return;

    const pill = document.createElement("span");
    pill.className = "builder-pill";
    pill.draggable = false;
    pill.innerHTML = `
      <span class="builder-pill-icon">${escapeHtml(item.iconLabel || item.label.slice(0, 2))}</span>
      <span>${escapeHtml(item.label)}</span>
      <button type="button" class="builder-pill-remove" aria-label="Quitar ${escapeHtml(item.label)}">×</button>`;
    pill.querySelector(".builder-pill-remove")?.addEventListener("click", () => {
      replaceWizardProfileDraft(type === "technology"
        ? removeTechnologyFromDraft(wizardProfileDraft, id)
        : removeScannerFromDraft(wizardProfileDraft, id));
      renderProfileCards();
    });
    row.appendChild(pill);
  });
}

function wireProfileBuilderDnD() {
  profileCards.querySelectorAll("[draggable='true']").forEach((pill) => {
    pill.addEventListener("dragstart", (event) => {
      const payload = {
        type: pill.dataset.dragType,
        id: pill.dataset.itemId,
      };
      event.dataTransfer.effectAllowed = "copy";
      event.dataTransfer.setData("application/json", JSON.stringify(payload));
      event.dataTransfer.setData("text/plain", payload.id);
      pill.classList.add("dragging");
    });
    pill.addEventListener("dragend", () => pill.classList.remove("dragging"));
  });

  profileCards.querySelectorAll("[data-drop-slot]").forEach((zone) => {
    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.classList.add("drag-over");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("drag-over");
      handleProfileBuilderDrop(event, zone.dataset.dropSlot);
    });
  });

  profileCards.querySelector("#builder-reuse-profile")?.addEventListener("change", (event) => {
    wizardProfileDraft = {
      ...wizardProfileDraft,
      applySavedProfileToNextProjects: event.target.checked,
    };
  });
}

function handleProfileBuilderDrop(event, dropSlot) {
  const payload = readDragPayload(event);
  if (!payload) {
    showBuilderRejected(dropSlot, "No se pudo leer el elemento arrastrado.");
    return;
  }

  if (dropSlot === "technologies") {
    if (payload.type !== "technology") {
      showBuilderRejected(dropSlot, "Suelta tecnologias en esta zona.");
      return;
    }
    replaceWizardProfileDraft(addTechnologyToDraft(wizardProfileDraft, payload.id));
    renderProfileCards();
    return;
  }

  if (payload.type !== "scanner") {
    showBuilderRejected(dropSlot, "Suelta scanners en este bloque.");
    return;
  }

  const scanner = findScanner(payload.id);
  if (!scanner) {
    showBuilderRejected(dropSlot, "Scanner desconocido.");
    return;
  }

  if (scanner.slot !== dropSlot) {
    showBuilderRejected(dropSlot, `${scanner.label} pertenece al bloque ${slotLabel(scanner.slot)}.`);
    return;
  }

  const nextDraft = addScannerToDraft(wizardProfileDraft, payload.id);
  const rejected = nextDraft.validation?.rejectedDrop;
  replaceWizardProfileDraft(nextDraft);
  renderProfileCards();
  if (rejected) animateRejectedDrop(dropSlot);
}

function readDragPayload(event) {
  try {
    return JSON.parse(event.dataTransfer.getData("application/json"));
  } catch {
    return null;
  }
}

function showBuilderRejected(dropSlot, message) {
  wizardProfileDraft = {
    ...applyValidation(wizardProfileDraft),
    validation: {
      ...applyValidation(wizardProfileDraft).validation,
      rejectedDrop: { itemId: dropSlot, message },
    },
  };
  renderProfileCards();
  animateRejectedDrop(dropSlot);
}

function animateRejectedDrop(dropSlot) {
  const zone = profileCards.querySelector(`[data-drop-slot="${dropSlot}"]`);
  if (!zone) return;
  zone.classList.add("drop-rejected");
  window.setTimeout(() => zone.classList.remove("drop-rejected"), 260);
}

function replaceWizardProfileDraft(nextDraft, preserveSavedProfile = false) {
  wizardProfileDraft = preserveSavedProfile
    ? nextDraft
    : {
        ...nextDraft,
        savedSessionProfile: null,
        applySavedProfileToNextProjects: wizardProfileDraft.applySavedProfileToNextProjects,
      };
}

function renderBuilderValidationMessage() {
  const message = profileCards.querySelector("#profile-builder-message");
  if (!message) return;

  const validation = wizardProfileDraft.validation || {};
  const rejectedMessage = validation.rejectedDrop?.message;
  const firstError = validation.errors?.[0];
  const firstWarning = validation.warnings?.[0];

  if (rejectedMessage || firstError) {
    message.className = "builder-message visible error";
    message.textContent = rejectedMessage || firstError;
    return;
  }

  if (firstWarning) {
    message.className = "builder-message visible warning";
    message.textContent = firstWarning;
    return;
  }

  if (validation.isValid) {
    const scanners = getAllSelectedScannerIds(wizardProfileDraft).map((id) => findScanner(id)?.label).filter(Boolean);
    message.className = "builder-message visible success";
    message.textContent = `Perfil valido: ${scanners.join(" + ")}`;
    return;
  }

  message.className = "builder-message";
  message.textContent = "";
}

function updateWizardNextButton() {
  if (!wizardNextBtn) return;
  const isValid = Boolean(wizardProfileDraft.validation?.isValid);
  wizardNextBtn.disabled = !isValid;
  wizardNextBtn.style.opacity = isValid ? "1" : ".52";
  wizardNextBtn.style.cursor = isValid ? "pointer" : "not-allowed";
}

function slotLabel(slot) {
  return {
    sast: "SAST",
    dast: "DAST",
    sca: "SCA",
    quality: "Quality",
  }[slot] || slot;
}

function slotHint(slot) {
  return {
    sast: "Codigo fuente y reglas seguras",
    dast: "Aplicacion en ejecucion",
    sca: "Dependencias y librerias",
    quality: "Calidad y mantenibilidad",
  }[slot] || "Configura scanners";
}

function renderTechChipsForStep2() {
  const techs = wizardProfileDraft.selectedTechnologies || [];
  const primary = getPrimaryApiTechnology(wizardProfileDraft);
  ["zip-tech-chip", "repo-tech-chip"].forEach((id) => {
    const chip = document.getElementById(id);
    if (!chip) return;
    if (!techs.length) { chip.style.display = "none"; return; }
    const items = techs.map((tech) => {
      const isPrimary = tech === primary;
      const primarySuffix = isPrimary && techs.length > 1
        ? ` <span class="tech-label">${t("tech-chip-primary")}</span>`
        : "";
      const cls = isPrimary ? "primary" : "secondary";
      return `<span class="tech-${cls}">${escapeHtml(tech)}${primarySuffix}</span>`;
    });
    chip.innerHTML =
      `<span class="tech-label">${t("tech-chip-label")}:</span> ` +
      items.join(" · ") +
      ` <span class="tech-label">· ${t("tech-chip-from-profile")}</span>`;
    chip.style.display = "";
  });
}

async function renderCompatibleProjects() {
  if (!compatibleProjectsList) return;
  compatibleProjectsList.innerHTML = `<div class="compatible-project-empty">Cargando proyectos...</div>`;
  if (compatibleProjectsStatus) {
    compatibleProjectsStatus.textContent = "Validando tecnologia contra el perfil seleccionado.";
  }

  try {
    const allProjects = await getProjects();
    const compatibleProjects = allProjects.filter((project) =>
      isProjectCompatibleWithProfile(project, wizardProfileDraft)
    );

    compatibleProjectsList.innerHTML = "";
    if (!compatibleProjects.length) {
      compatibleProjectsList.innerHTML =
        `<div class="compatible-project-empty">No hay proyectos compatibles todavia. Sube un ZIP o clona un repositorio.</div>`;
      if (compatibleProjectsStatus) {
        compatibleProjectsStatus.textContent = "No hay proyectos compatibles con este perfil.";
      }
      return;
    }

    if (compatibleProjectsStatus) {
      compatibleProjectsStatus.textContent = `${compatibleProjects.length} proyecto(s) compatible(s) con este perfil.`;
    }

    compatibleProjects.forEach((project) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "compatible-project-card";
      button.innerHTML = `
        <strong>${escapeHtml(project.name)}</strong>
        <span>${escapeHtml(project.technology)} · ${escapeHtml(project.source_type || "proyecto")}</span>
        <span>${Number(project.finding_count || 0)} hallazgos registrados</span>`;
      button.addEventListener("click", () => chooseCompatibleProject(project, button));
      compatibleProjectsList.appendChild(button);
    });
  } catch (error) {
    compatibleProjectsList.innerHTML =
      `<div class="compatible-project-empty">No se pudieron cargar los proyectos.</div>`;
    if (compatibleProjectsStatus) {
      compatibleProjectsStatus.textContent = error.message || "Error al cargar proyectos.";
    }
  }
}

async function chooseCompatibleProject(project, button) {
  try {
    button.disabled = true;
    button.style.opacity = ".65";
    const profileId = await resolvedProfileIdForTechnology(project.technology);
    const updatedProject = profileId !== null
      ? await assignProjectProfile(project.id, profileId)
      : project;
    hideProjectModal();
    if (onExistingProjectSelected) await onExistingProjectSelected(updatedProject);
    showFeedback(`Proyecto seleccionado: ${project.name}`, "success");
  } catch (error) {
    button.disabled = false;
    button.style.opacity = "";
    showFeedback(
      `No se pudo seleccionar el proyecto: ${formatApiError(error.detail, error.message)}`,
      "error"
    );
  }
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
  const skipProfileStep = wizardStep1?.dataset.skipProfile === "true";
  if (!onStep1 && !skipProfileStep) {
    wizardProfileDraft = applyValidation(wizardProfileDraft);
    if (!wizardProfileDraft.validation.isValid) {
      renderProfileCards();
      return;
    }
    renderTechChipsForStep2();
  }
  wizardStep1.style.display = onStep1 ? "" : "none";
  wizardStep2.style.display = onStep1 ? "none" : "";
  bcStep1.style.color = onStep1 ? "var(--accent)" : "var(--muted)";
  bcStep2.style.color = onStep1 ? "var(--muted)" : "var(--accent)";
  if (!onStep1) setModalTab("zip");
  if (!onStep1) renderCompatibleProjects();
}

function resolvedProfileId() {
  return wizardProfileDraft.savedSessionProfile?.id ?? null;
}

async function resolvedProfileIdForTechnology(technology) {
  const existingProfileId = resolvedProfileId();
  if (existingProfileId) {
    return existingProfileId;
  }

  const hasDraftProfile = Boolean(
    wizardProfileDraft.selectedTechnologies?.length &&
    getAllSelectedScannerIds(wizardProfileDraft).length
  );
  if (!hasDraftProfile) return null;

  const selectedTechnology = String(technology || "").trim().toLowerCase();
  const profileTechnologies = getApiTechnologiesFromState(wizardProfileDraft);
  if (selectedTechnology && profileTechnologies.length && !profileTechnologies.includes(selectedTechnology)) {
    throw new Error(`El perfil armado es para ${profileTechnologies.join(", ")}; ajusta la tecnologia del proyecto o vuelve a configurar el perfil.`);
  }

  const payload = toScanProfilePayload(wizardProfileDraft);
  const data = await createProfile(payload);
  wizardProfiles.push(data);
  const savedSessionProfile = wizardProfileDraft.applySavedProfileToNextProjects
    ? saveSessionProfile(data, wizardProfileDraft)
    : null;
  wizardProfileDraft = {
    ...wizardProfileDraft,
    savedSessionProfile,
  };
  return data.id;
}

export function showProjectModal(profile = null) {
  if (wizardProfiles.length === 0) loadWizardProfiles();
  const savedProfile = loadSessionProfile();
  if (profile) {
    wizardProfileDraft = profileToDraft(profile);
  } else if (savedProfile?.draft) {
    wizardProfileDraft = {
      ...applyValidation(savedProfile.draft),
      savedSessionProfile: savedProfile,
      applySavedProfileToNextProjects: true,
    };
  } else {
    wizardProfileDraft = applyValidation(createEmptyProfileBuilderState());
  }
  if (profile) {
    wizardProfileDraft.savedSessionProfile = saveSessionProfile(profile, wizardProfileDraft);
    wizardProfileDraft.applySavedProfileToNextProjects = true;
  }
  wizardSelectedProfileId = "builder";
  wizardStep1.dataset.skipProfile = "true";
  const backZip = document.getElementById("wizard-back-zip");
  const backClone = document.getElementById("wizard-back-clone");
  if (backZip) backZip.style.display = "none";
  if (backClone) backClone.style.display = "none";
  projectModal.style.display = "flex";
  renderTechChipsForStep2();
  setWizardStep(2);
}

export function hideProjectModal() {
  projectModal.style.display = "none";
  wizardSelectedProfileId = null;
  wizardStep1.dataset.skipProfile = "";
  const backZip = document.getElementById("wizard-back-zip");
  const backClone = document.getElementById("wizard-back-clone");
  if (backZip) backZip.style.display = "";
  if (backClone) backClone.style.display = "";
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
    const technology = getPrimaryApiTechnology(wizardProfileDraft) || "python";
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
    technology: getPrimaryApiTechnology(wizardProfileDraft) || "python",
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
