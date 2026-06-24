// ── project-selector.js — standalone project selection page ──────────────────
import { escapeHtml, showFeedback } from "/static/js/utils.js";
import {
  getProjects, forkProject, uploadZip, cloneRepo,
} from "/static/js/api.js";
import {
  loadSessionProfile, isProjectCompatibleWithProfile, getPrimaryApiTechnology,
} from "/static/js/profile-builder-state.js";

const PENDING_PROJECT_KEY = "ai-devsecops.pendingProject";

const projectsGrid         = document.getElementById("projects-grid");
const compatibleCount      = document.getElementById("compatible-count");
const profileContextLine   = document.getElementById("profile-context-line");
const tabZip               = document.getElementById("tab-zip");
const tabClone             = document.getElementById("tab-clone");
const panelZip             = document.getElementById("panel-zip");
const panelClone           = document.getElementById("panel-clone");
const cloneGhBtn           = document.getElementById("clone-gh");
const cloneGlBtn           = document.getElementById("clone-gl");
const repoUrlInput         = document.getElementById("repo-url");
const uploadForm           = document.getElementById("upload-project-form");
const cloneForm            = document.getElementById("clone-project-form");

const sessionProfile = loadSessionProfile();
const profileDraft   = sessionProfile?.draft ?? null;

// Show profile context badge if a profile is in session
if (sessionProfile?.name) {
  profileContextLine.textContent =
    `Perfil activo: ${sessionProfile.name}. Selecciona un proyecto compatible o agrega uno nuevo.`;
}

// Show technology chip if profile has a primary tech
function renderTechChips() {
  if (!profileDraft) return;
  const primary = getPrimaryApiTechnology(profileDraft);
  if (!primary) return;
  ["zip-tech-chip", "repo-tech-chip"].forEach((id) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = `Tecnología del perfil: ${primary}`;
    el.style.display = "";
  });
}
renderTechChips();

// ── Tab switching ─────────────────────────────────────────────────────────────
function setTab(tab) {
  const isZip = tab === "zip";
  tabZip.className   = "tab-btn " + (isZip ? "tab-active" : "tab-inactive");
  tabClone.className = "tab-btn " + (isZip ? "tab-inactive" : "tab-active");
  panelZip.className   = "form-panel " + (isZip ? "visible-panel" : "hidden-panel") + " ps-form-card";
  panelClone.className = "form-panel " + (isZip ? "hidden-panel" : "visible-panel") + " ps-form-card";
}
tabZip.addEventListener("click",   () => setTab("zip"));
tabClone.addEventListener("click", () => setTab("clone"));

function setCloneSource(source) {
  cloneGhBtn.className = "tab-btn " + (source === "gh" ? "tab-active" : "tab-inactive");
  cloneGlBtn.className = "tab-btn " + (source === "gl" ? "tab-active" : "tab-inactive");
  repoUrlInput.placeholder = source === "gh"
    ? "https://github.com/usuario/repo.git"
    : "https://gitlab.com/usuario/repo.git";
}
cloneGhBtn.addEventListener("click", () => setCloneSource("gh"));
cloneGlBtn.addEventListener("click", () => setCloneSource("gl"));

// ── Navigation back to dashboard ──────────────────────────────────────────────
function navigateToProject(project) {
  sessionStorage.setItem(PENDING_PROJECT_KEY, JSON.stringify(project));
  window.location.href = "/#projects";
}

// ── Projects grid ─────────────────────────────────────────────────────────────
async function loadProjects() {
  projectsGrid.innerHTML =
    `<div class="compatible-project-empty" style="grid-column:1/-1;">Cargando proyectos...</div>`;

  try {
    const all = await getProjects();
    const filtered = profileDraft
      ? all.filter((p) => isProjectCompatibleWithProfile(p, profileDraft))
      : all;

    projectsGrid.innerHTML = "";

    if (!filtered.length) {
      projectsGrid.innerHTML =
        `<div class="compatible-project-empty" style="grid-column:1/-1;">` +
        `No hay proyectos disponibles. Sube un ZIP o clona un repositorio.</div>`;
      compatibleCount.textContent = "0 proyectos disponibles";
      return;
    }

    const suffix = profileDraft
      ? `proyecto(s) compatible(s) con este perfil.`
      : `proyecto(s) disponibles.`;
    compatibleCount.textContent = `${filtered.length} ${suffix}`;

    filtered.forEach((project) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "compatible-project-card";
      btn.innerHTML = `
        <strong>${escapeHtml(project.name)}</strong>
        <span>${escapeHtml(project.technology)} · ${escapeHtml(project.source_type || "proyecto")}</span>
        <span style="color:var(--accent);font-size:.72rem;">Nuevo análisis con este código →</span>`;
      btn.addEventListener("click", () => selectExistingProject(project, btn));
      projectsGrid.appendChild(btn);
    });
  } catch (err) {
    projectsGrid.innerHTML =
      `<div class="compatible-project-empty" style="grid-column:1/-1;">No se pudieron cargar los proyectos.</div>`;
    compatibleCount.textContent = err.message || "Error al cargar";
  }
}

async function selectExistingProject(project, btn) {
  btn.disabled = true;
  btn.style.opacity = ".65";
  try {
    const payload = { scan_profile_id: sessionProfile?.id ?? null };
    const newProject = await forkProject(project.id, payload);
    navigateToProject(newProject);
  } catch (err) {
    btn.disabled = false;
    btn.style.opacity = "";
    showFeedback(`No se pudo crear el proyecto: ${err.message}`, "error");
  }
}

// ── ZIP upload ────────────────────────────────────────────────────────────────
uploadForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fileInput = document.getElementById("zip-file");
  if (!fileInput.files.length) {
    showFeedback("Selecciona un archivo ZIP.", "error");
    return;
  }

  const btn  = uploadForm.querySelector("button[type='submit']");
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Cargando…";

  try {
    const technology = (profileDraft && getPrimaryApiTechnology(profileDraft)) || "python";
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);
    formData.append("name", document.getElementById("zip-name").value);
    formData.append("technology", technology);
    if (sessionProfile?.id) formData.append("scan_profile_id", String(sessionProfile.id));

    const result = await uploadZip(formData);
    navigateToProject(result.project);
  } catch (err) {
    showFeedback(`No se pudo crear el proyecto: ${err.message}`, "error");
    btn.disabled = false;
    btn.textContent = orig;
  }
});

// ── Repo clone ────────────────────────────────────────────────────────────────
cloneForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = document.getElementById("repo-name").value.trim();
  const url  = document.getElementById("repo-url").value.trim();
  if (!name || !url) {
    showFeedback("Nombre y URL son obligatorios.", "error");
    return;
  }

  const btn  = cloneForm.querySelector("button[type='submit']");
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Clonando…";

  try {
    const technology = (profileDraft && getPrimaryApiTechnology(profileDraft)) || "python";
    const payload = { name, repo_url: url, technology };
    if (sessionProfile?.id) payload.scan_profile_id = sessionProfile.id;

    const result = await cloneRepo(payload);
    navigateToProject(result.project);
  } catch (err) {
    showFeedback(`No se pudo clonar: ${err.message}`, "error");
    btn.disabled = false;
    btn.textContent = orig;
  }
});

// ── Boot ──────────────────────────────────────────────────────────────────────
loadProjects();
