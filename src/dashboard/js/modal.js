// ── modal.js — all modal lifecycle, PR, audit ─────────────────────────────────
import {
  t, escapeHtml, showFeedback, formatApiError, cleanCodeFences, shortPath,
  BANDIT_ES,
} from "/static/js/utils.js";
import {
  getRemediationPr, createPR, deletePRBranch,
  getPRDiff, getSourceFile, getAuditHistory, postLifecycleAction,
  getRemediationPreview,
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

// ── Module state ─────────────────────────────────────────────────────────────
let currentRemediationFindingId;
let currentPrBranch;
let _diffHunkInfo = null;
let _diffFileData = null;
let _usingGitHubDiff = false;
let reasonModalCallback = null;
// P1 fix: epoch counter — incremented every time a new finding modal is opened.
// All async callbacks capture their epoch at launch and abort if it no longer
// matches _modalEpoch, preventing stale results from overwriting the current one.
let _modalEpoch = 0;

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
function renderPullRequestSuccess(prUrl, prType) {
  prActionContainer.innerHTML = "";
  const wrap = document.createElement("div");
  wrap.style.cssText = "display:flex;align-items:center;gap:10px;flex-wrap:wrap;";

  const link = document.createElement("a");
  link.href = prUrl; link.target = "_blank"; link.rel = "noopener noreferrer";
  link.style.cssText = "color:var(--accent);font-size:.83rem;text-decoration:underline;";
  link.textContent = "🔗 Ver Pull Request en GitHub";

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

  try {
    const diffData = await getPRDiff(findingId);
    if (epoch !== undefined && epoch !== _modalEpoch) return false;

    if (diffData && diffData.diff) {
      renderGitHubDiff(diffView, diffData.diff);
      return true;
    }

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
  const epoch = ++_modalEpoch;
  const shouldCheckExistingPr = record.has_remediation && selectedProject?.source_type === "repo";

  currentRemediationFindingId = record.id;
  currentPrBranch = undefined;
  _usingGitHubDiff = false;
  _diffFileData = null;
  _diffHunkInfo = null;

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

  (async (capturedEpoch) => {
    const hasRemediation = Boolean(record.has_remediation);
    const [fileResult, previewResult] = await Promise.allSettled([
      getSourceFile(record.id),
      hasRemediation ? getRemediationPreview(record.id) : Promise.resolve(null),
    ]);

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

async function checkExistingPR(record, cleanPatch, epoch) {
  const findingId = record.id;
  try {
    const data = await getRemediationPr(findingId);
    if (epoch !== _modalEpoch) return;
    if (!data || !data.pr_url) {
      _usingGitHubDiff = false;
      return;
    }

    _usingGitHubDiff = true;
    currentPrBranch = data.branch;
    renderPullRequestSuccess(data.pr_url, data.pr_type);
    await renderGitHubPrDiff(findingId, epoch);
  } catch (err) {
    if (epoch !== _modalEpoch) return;
    console.warn("[checkExistingPR] error:", err);
    _usingGitHubDiff = false;
  }
}

export function hideRemediationModal() {
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
    const onCancel  = () => close(false);
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
      regression:    "Regresión detectada",
      accept_risk:   "Riesgo aceptado",
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
export function wireModalEvents() {
  closeRemediationButton.addEventListener("click", hideRemediationModal);
  remediationModal.addEventListener("click", (e) => { if (e.target === remediationModal) hideRemediationModal(); });

  createPrButton.addEventListener("click", createPullRequest);

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
