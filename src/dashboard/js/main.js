// ── main.js — entry point: DOMContentLoaded + boot ───────────────────────────
import {
  currentLang, setLang, applyI18n, t,
} from "/static/js/utils.js";
import {
  renderAiStatusBadge, wireDashboardEvents, loadAiStatus, loadProjects, selectProject,
  currentFindings, projects, selectedProject, renderRows, updateFloatingNav,
} from "/static/js/dashboard.js";
import {
  wireModalEvents, setOnProjectCreated, showProjectModal,
} from "/static/js/modal.js";

// ── Wire all events ───────────────────────────────────────────────────────────
wireDashboardEvents();
wireModalEvents();

// When a project is created via the wizard, refresh and select it
setOnProjectCreated(async (project) => {
  await loadProjects(false);
  if (project) await selectProject(project);
});

// New-project button
document.getElementById("new-project")?.addEventListener("click", showProjectModal);

// Language toggle
const langToggle    = document.getElementById("lang-toggle");
const tableStatus   = document.getElementById("table-status");
const projectStatus = document.getElementById("project-status");

if (langToggle) {
  langToggle.textContent = currentLang === "es" ? "ES" : "EN";
  langToggle.addEventListener("click", () => {
    const next = currentLang === "es" ? "en" : "es";
    setLang(next);
    langToggle.textContent = next === "es" ? "ES" : "EN";
    langToggle.style.fontWeight = "700";
    applyI18n();
    renderAiStatusBadge();
    if (currentFindings.length > 0) renderRows(currentFindings);
    if (selectedProject && tableStatus) {
      tableStatus.textContent =
        `${currentFindings.length} ${t("findings-loaded")} · ${selectedProject.technology} · ${selectedProject.source_type}`;
    }
    if (projectStatus) {
      projectStatus.textContent = `${projects.length} ${t("registered-projects")}`;
    }
  });
}

// Floating nav on scroll
window.addEventListener("scroll", updateFloatingNav, { passive: true });
updateFloatingNav();

// ── Boot sequence ─────────────────────────────────────────────────────────────
if (window.location.hash) {
  history.replaceState(null, "", window.location.pathname + window.location.search);
  window.scrollTo(0, 0);
}

applyI18n();
renderAiStatusBadge();
loadAiStatus();
loadProjects();
