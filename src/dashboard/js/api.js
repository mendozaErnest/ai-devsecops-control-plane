// ── api.js — all HTTP fetch() calls centralised ──────────────────────────────

export async function getProjects() {
  const res = await fetch("/api/projects");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getProjectFindings(projectId) {
  const res = await fetch(`/api/projects/${projectId}/findings`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function assignProjectProfile(projectId, profileId) {
  const res = await fetch(`/api/projects/${projectId}/profile`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scan_profile_id: profileId ?? null }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}

export async function scanProject(projectId, targetUrl = null) {
  const body = { project_id: projectId };
  if (targetUrl) body.target_url = targetUrl;
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}

export async function uploadZip(formData) {
  const res = await fetch("/api/projects/upload-zip", { method: "POST", body: formData });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}

export async function cloneRepo(payload) {
  const res = await fetch("/api/projects/clone-repo", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}

export async function getAiStatus() {
  const res = await fetch("/api/ai-status");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function generateRemediation(findingId) {
  const res = await fetch(`/api/remediate/${findingId}`, { method: "POST" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}

export async function getRemediationPr(findingId) {
  const res = await fetch(`/api/remediate/${findingId}/pr`);
  if (!res.ok) return null;
  return res.json();
}

export async function createPR(findingId) {
  const res = await fetch(`/api/remediate/${findingId}/pr`, { method: "POST" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}

export async function deletePRBranch(findingId) {
  const res = await fetch(`/api/remediate/${findingId}/pr`, { method: "DELETE" });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}

export async function getPRDiff(findingId) {
  const res = await fetch(`/api/findings/${findingId}/pr-diff`);
  if (!res.ok) return null;
  return res.json();
}

export async function getSourceFile(findingId) {
  const res = await fetch(`/api/findings/${findingId}/file_content`);
  if (!res.ok) return null;
  return res.json();
}

export async function getAuditHistory(findingId) {
  const res = await fetch(`/api/findings/${findingId}/audit`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function postLifecycleAction(findingId, action, reason) {
  const res = await fetch(`/api/findings/${findingId}/${action}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json().catch(() => ({}));
}

export async function getProfiles() {
  const res = await fetch("/api/profiles");
  if (!res.ok) return [];
  return res.json();
}

export async function createProfile(payload) {
  const res = await fetch("/api/profiles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}

export async function getReport(projectId) {
  const res = await fetch(`/api/reports/project/${projectId}`);
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json();
}

/**
 * Fetch the exact before/after file content that the remediation PR would commit.
 * Returns { original: string, patched: string } or null if unavailable.
 */
export async function getRemediationPreview(findingId) {
  const res = await fetch(`/api/remediate/${findingId}/preview-diff`);
  if (!res.ok) return null;
  return res.json();
}

export async function triggerScan(projectId, profileId = null) {
  const body = { project_id: projectId };
  if (profileId !== null) body.profile_id = profileId;
  const res = await fetch("/api/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(), { detail: data.detail, status: res.status, data });
  return data;
}
