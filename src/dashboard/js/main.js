// ── main.js — entry point: DOMContentLoaded + boot ───────────────────────────
import {
  currentLang, setLang, applyI18n, t,
} from "/static/js/utils.js";
import {
  renderAiStatusBadge, wireDashboardEvents, loadAiStatus, loadProjects, selectProject,
  currentFindings, projects, selectedProject, renderRows, updateFloatingNav,
} from "/static/js/dashboard.js";
import {
  wireModalEvents, setOnProjectCreated, setOnExistingProjectSelected, showProjectModal,
} from "/static/js/modal.js";
import { initProfileBuilderView } from "/static/js/profile-builder-view.js";

const configurationView = document.getElementById("configuration-view");
const projectsView = document.getElementById("projects-view");
const appViewLinks = document.querySelectorAll("[data-app-view-link]");

const VALID_VIEWS = new Set(["configuration", "projects", "reports"]);

function showAppView(view, push = true) {
  const targetView = view === "reports" ? "projects" : view;
  if (configurationView) configurationView.style.display = targetView === "configuration" ? "" : "none";
  if (projectsView) projectsView.style.display = targetView === "projects" ? "" : "none";

  appViewLinks.forEach((link) => {
    link.classList.toggle("on", link.dataset.appViewLink === view);
  });

  if (view === "projects") document.getElementById("view-findings-btn")?.click();
  if (view === "reports")  document.getElementById("view-report-btn")?.click();

  if (push) {
    history.pushState({ view }, "", `#${view}`);
  }
}

window.addEventListener("popstate", (e) => {
  const view = e.state?.view;
  if (VALID_VIEWS.has(view)) showAppView(view, false);
});

// ── Wire all events ───────────────────────────────────────────────────────────
wireDashboardEvents();
wireModalEvents();
initProfileBuilderView({
  onOpenProjectsView: () => showAppView("projects"),
  onAddProject: (profile = null) => showProjectModal(profile),
});

// When a project is created via the wizard, refresh and select it
setOnProjectCreated(async (project) => {
  await loadProjects(false);
  if (project) await selectProject(project);
  showAppView("projects");
});

setOnExistingProjectSelected(async (project) => {
  await loadProjects(false);
  if (project) await selectProject(project);
  showAppView("projects");
});

// New-project button
document.getElementById("new-project")?.addEventListener("click", () => showProjectModal());
appViewLinks.forEach((link) => {
  link.addEventListener("click", (event) => {
    event.preventDefault();
    showAppView(link.dataset.appViewLink);
  });
});

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
applyI18n();
renderAiStatusBadge();
loadAiStatus();
loadProjects();

const bootView = window.location.hash.slice(1);
const initialView = VALID_VIEWS.has(bootView) ? bootView : "configuration";
history.replaceState({ view: initialView }, "", `#${initialView}`);
showAppView(initialView, false);
