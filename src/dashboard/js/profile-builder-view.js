import { createProfile, getProfiles } from "/static/js/api.js";
import { escapeHtml, formatApiError, showFeedback } from "/static/js/utils.js";
import {
  PROFILE_BUILDER_STORAGE_KEY,
  SCAN_SLOT_ORDER,
  TECHNOLOGY_ITEMS,
  SCANNER_ITEMS,
  addScannerToDraft,
  addTechnologyToDraft,
  applyValidation,
  canDropScannerOnTechnology,
  createEmptyProfileBuilderState,
  findScanner,
  findTechnology,
  getAllSelectedScannerIds,
  loadSessionProfile,
  profileToDraft,
  removeScannerFromDraft,
  removeTechnologyFromDraft,
  saveSessionProfile,
  toScanProfilePayload,
} from "/static/js/profile-builder-state.js";

const builderRoot = document.getElementById("home-profile-builder");
const savedProfilesList = document.getElementById("saved-profiles-list");
const refreshProfilesButton = document.getElementById("refresh-profiles");
const resetBuilderButton = document.getElementById("profile-builder-reset");
const builderNewProjectButton = document.getElementById("builder-new-project");
const goProjectsButton = document.getElementById("go-projects-view");

let profileDraft = createEmptyProfileBuilderState();
let savedProfiles = [];
let onOpenProjectsView = null;
let onAddProject = null;

export function initProfileBuilderView(options = {}) {
  onOpenProjectsView = options.onOpenProjectsView || null;
  onAddProject = options.onAddProject || null;

  const savedProfile = loadSessionProfile();
  profileDraft = savedProfile?.draft
    ? {
        ...applyValidation(savedProfile.draft),
        savedSessionProfile: savedProfile,
        applySavedProfileToNextProjects: true,
      }
    : applyValidation(createEmptyProfileBuilderState());

  renderProfileBuilder();
  loadSavedProfiles();

  refreshProfilesButton?.addEventListener("click", loadSavedProfiles);
  resetBuilderButton?.addEventListener("click", () => {
    profileDraft = applyValidation(createEmptyProfileBuilderState());
    window.sessionStorage?.removeItem(PROFILE_BUILDER_STORAGE_KEY);
    renderProfileBuilder();
    renderSavedProfiles();
  });
  builderNewProjectButton?.addEventListener("click", openProjectWithCurrentProfile);
  goProjectsButton?.addEventListener("click", () => onOpenProjectsView?.());
}

export async function loadSavedProfiles() {
  if (!savedProfilesList) return;
  savedProfilesList.innerHTML = `<p style="color:var(--t-dim);font-size:12px;padding:10px;">Cargando configuraciones...</p>`;
  try {
    savedProfiles = await getProfiles();
    renderSavedProfiles();
  } catch (error) {
    savedProfilesList.innerHTML = `<p style="color:#ff7b72;font-size:12px;padding:10px;">No se pudieron cargar perfiles.</p>`;
    showFeedback(`No se pudieron cargar perfiles: ${error.message}`, "error");
  }
}

function renderProfileBuilder() {
  if (!builderRoot) return;
  profileDraft = applyValidation(profileDraft);
  builderRoot.innerHTML = "";

  const palette = document.createElement("aside");
  palette.className = "builder-palette";
  palette.appendChild(renderPaletteSection("Tecnologias", TECHNOLOGY_ITEMS, "technology"));
  palette.appendChild(renderPaletteSection("Scanners", SCANNER_ITEMS, "scanner"));

  const dropzone = document.createElement("section");
  dropzone.className = "builder-dropzone";
  dropzone.innerHTML = `
    <div class="builder-technology-zone" data-drop-zone="technologies">
      <div class="builder-zone-head">
        <div>
          <p class="builder-zone-title">Tecnologias del proyecto</p>
          <p class="builder-zone-hint">Arrastra una o mas tecnologias</p>
        </div>
      </div>
      <div class="builder-selected-row" data-selected-row="technologies"></div>
    </div>

    <div class="builder-single-scanner-zone" data-drop-zone="scanners">
      <div class="builder-zone-head">
        <div>
          <p class="builder-zone-title">Scanners seleccionados</p>
          <p class="builder-zone-hint">Suelta cualquier scanner aqui; el perfil suma su capacidad automaticamente</p>
        </div>
      </div>
      <div class="builder-selected-row" data-selected-row="scanners"></div>
    </div>

    <label class="builder-name-field">
      <span>Nombre de la configuracion</span>
      <input id="home-builder-profile-name" type="text" value="${escapeHtml(profileDraft.profileName || "")}" placeholder="Ej. Python backend completo">
    </label>

    <div class="builder-capability-summary">
      ${SCAN_SLOT_ORDER.map((slot) => renderCapabilityMarkup(slot)).join("")}
    </div>

    <div id="home-builder-message" class="builder-message"></div>

    <div class="builder-session-row">
      <span>${profileDraft.savedSessionProfile ? `Perfil activo: ${escapeHtml(profileDraft.savedSessionProfile.name)}` : "Guarda una configuracion para usarla en nuevos proyectos."}</span>
      <label>
        <input id="home-builder-reuse-profile" type="checkbox" ${profileDraft.applySavedProfileToNextProjects ? "checked" : ""}>
        Reusar en proyectos siguientes
      </label>
    </div>

    <div class="builder-action-row">
      <button type="button" id="home-builder-save" class="btn primary">Guardar configuracion</button>
      <button type="button" id="home-builder-open-project" class="btn">Agregar proyecto con este perfil</button>
    </div>`;

  builderRoot.appendChild(palette);
  builderRoot.appendChild(dropzone);

  renderSelectedPills("technologies", profileDraft.selectedTechnologies, "technology");
  renderSelectedPills("scanners", getAllSelectedScannerIds(profileDraft), "scanner");
  renderCapabilities();
  wireDragAndDrop();
  wireBuilderActions();
  renderBuilderMessage();
}

function renderPaletteSection(title, items, type) {
  const section = document.createElement("div");
  const titleEl = document.createElement("p");
  titleEl.className = "builder-section-title";
  titleEl.textContent = title;

  const list = document.createElement("div");
  list.className = "builder-pill-list";
  items.forEach((item) => list.appendChild(renderDraggablePill(item, type)));

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
  pill.innerHTML = `
    <span class="builder-pill-icon">${escapeHtml(item.iconLabel || item.label.slice(0, 2))}</span>
    <span>${escapeHtml(item.label)}</span>`;
  pill.addEventListener("click", () => {
    replaceDraft(type === "technology"
      ? addTechnologyWithCompatibility(item.id)
      : addScannerToDraft(profileDraft, item.id));
    renderProfileBuilder();
  });
  return pill;
}

function renderSelectedPills(rowName, itemIds, type) {
  const row = builderRoot.querySelector(`[data-selected-row="${rowName}"]`);
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
    pill.innerHTML = `
      <span class="builder-pill-icon">${escapeHtml(item.iconLabel || item.label.slice(0, 2))}</span>
      <span>${escapeHtml(item.label)}</span>
      <button type="button" class="builder-pill-remove" aria-label="Quitar ${escapeHtml(item.label)}">x</button>`;
    pill.querySelector(".builder-pill-remove")?.addEventListener("click", () => {
      replaceDraft(type === "technology"
        ? removeTechnologyFromDraft(profileDraft, id)
        : removeScannerFromDraft(profileDraft, id));
      renderProfileBuilder();
    });
    row.appendChild(pill);
  });
}

function renderCapabilityMarkup(slot) {
  return `
    <div class="builder-capability" data-capability="${slot}">
      <strong>${escapeHtml(slotLabel(slot))}</strong>
      <span>Sin scanners seleccionados</span>
    </div>`;
}

function renderCapabilities() {
  SCAN_SLOT_ORDER.forEach((slot) => {
    const capability = builderRoot.querySelector(`[data-capability="${slot}"]`);
    const box = capability?.querySelector("span");
    if (!capability || !box) return;
    const labels = (profileDraft.selectedScanners?.[slot] || [])
      .map((id) => findScanner(id)?.label)
      .filter(Boolean);
    capability.classList.toggle("covered", labels.length > 0);
    box.textContent = labels.length ? labels.join(" + ") : "Sin scanners seleccionados";
  });
}

function wireDragAndDrop() {
  builderRoot.querySelectorAll("[draggable='true']").forEach((pill) => {
    pill.addEventListener("dragstart", (event) => {
      const payload = { type: pill.dataset.dragType, id: pill.dataset.itemId };
      event.dataTransfer.effectAllowed = "copy";
      event.dataTransfer.setData("application/json", JSON.stringify(payload));
      pill.classList.add("dragging");
    });
    pill.addEventListener("dragend", () => pill.classList.remove("dragging"));
  });

  builderRoot.querySelectorAll("[data-drop-zone]").forEach((zone) => {
    zone.addEventListener("dragover", (event) => {
      event.preventDefault();
      zone.classList.add("drag-over");
    });
    zone.addEventListener("dragleave", () => zone.classList.remove("drag-over"));
    zone.addEventListener("drop", (event) => {
      event.preventDefault();
      zone.classList.remove("drag-over");
      handleDrop(event, zone.dataset.dropZone);
    });
  });
}

function handleDrop(event, zoneName) {
  const payload = readPayload(event);
  if (!payload) {
    rejectDrop(zoneName, "No se pudo leer el elemento arrastrado.");
    return;
  }

  if (zoneName === "technologies") {
    if (payload.type !== "technology") {
      rejectDrop(zoneName, "Suelta tecnologias en esta zona.");
      return;
    }
    replaceDraft(addTechnologyWithCompatibility(payload.id));
    renderProfileBuilder();
    return;
  }

  if (zoneName === "scanners") {
    if (payload.type !== "scanner") {
      rejectDrop(zoneName, "Suelta scanners en esta zona.");
      return;
    }
    const nextDraft = addScannerToDraft(profileDraft, payload.id);
    const rejected = nextDraft.validation?.rejectedDrop;
    replaceDraft(nextDraft);
    renderProfileBuilder();
    if (rejected) animateRejectedDrop(zoneName);
  }
}

function readPayload(event) {
  try {
    return JSON.parse(event.dataTransfer.getData("application/json"));
  } catch {
    return null;
  }
}

function rejectDrop(zoneName, message) {
  profileDraft = {
    ...applyValidation(profileDraft),
    validation: {
      ...applyValidation(profileDraft).validation,
      rejectedDrop: { itemId: zoneName, message },
    },
  };
  renderProfileBuilder();
  animateRejectedDrop(zoneName);
}

function addTechnologyWithCompatibility(technologyId) {
  for (const scannerId of getAllSelectedScannerIds(profileDraft)) {
    const result = canDropScannerOnTechnology(scannerId, technologyId, {
      targetUrl: profileDraft.targetUrl,
    });
    if (!result.ok) {
      return {
        ...applyValidation(profileDraft),
        validation: {
          ...applyValidation(profileDraft).validation,
          rejectedDrop: { itemId: technologyId, message: result.message },
        },
      };
    }
  }
  return addTechnologyToDraft(profileDraft, technologyId);
}

function animateRejectedDrop(zoneName) {
  const zone = builderRoot.querySelector(`[data-drop-zone="${zoneName}"]`);
  if (!zone) return;
  zone.classList.add("drop-rejected");
  window.setTimeout(() => zone.classList.remove("drop-rejected"), 260);
}

function wireBuilderActions() {
  const saveButton = builderRoot.querySelector("#home-builder-save");
  const openProjectButton = builderRoot.querySelector("#home-builder-open-project");
  const reuseCheckbox = builderRoot.querySelector("#home-builder-reuse-profile");
  const nameInput = builderRoot.querySelector("#home-builder-profile-name");

  nameInput?.addEventListener("input", (event) => {
    profileDraft = {
      ...profileDraft,
      profileName: event.target.value,
    };
  });

  if (saveButton) {
    const isValid = Boolean(profileDraft.validation?.isValid);
    saveButton.disabled = !isValid;
    saveButton.style.opacity = isValid ? "1" : ".52";
    saveButton.style.cursor = isValid ? "pointer" : "not-allowed";
    saveButton.addEventListener("click", saveCurrentProfile);
  }

  openProjectButton?.addEventListener("click", openProjectWithCurrentProfile);
  reuseCheckbox?.addEventListener("change", (event) => {
    profileDraft = {
      ...profileDraft,
      applySavedProfileToNextProjects: event.target.checked,
    };
  });
}

async function saveCurrentProfile() {
  const validated = applyValidation(profileDraft);
  if (!validated.validation.isValid) {
    profileDraft = validated;
    renderProfileBuilder();
    return null;
  }

  try {
    const payload = toScanProfilePayload(validated);
    const profile = await createProfile(payload);
    const savedSessionProfile = profileDraft.applySavedProfileToNextProjects
      ? saveSessionProfile(profile, validated)
      : null;
    profileDraft = {
      ...validated,
      savedSessionProfile,
    };
    showFeedback("Configuracion guardada y lista para nuevos proyectos.", "success");
    await loadSavedProfiles();
    renderProfileBuilder();
    return profile;
  } catch (error) {
    showFeedback(`No se pudo guardar la configuracion: ${formatApiError(error.detail, error.message)}`, "error");
    return null;
  }
}

async function openProjectWithCurrentProfile() {
  if (!profileDraft.savedSessionProfile?.id && !profileDraft.validation?.isValid) {
    profileDraft = applyValidation(profileDraft);
    renderProfileBuilder();
    return;
  }
  if (profileDraft.validation?.isValid && !profileDraft.savedSessionProfile?.id) {
    const profile = await saveCurrentProfile();
    if (!profile) return;
  }
  onAddProject?.(profileDraft.savedSessionProfile?.payload || null);
}

function renderBuilderMessage() {
  const message = builderRoot.querySelector("#home-builder-message");
  if (!message) return;

  const validation = profileDraft.validation || {};
  const rejected = validation.rejectedDrop?.message;
  const firstError = validation.errors?.[0];
  const firstWarning = validation.warnings?.[0];

  if (rejected || firstError) {
    message.className = "builder-message visible error";
    message.textContent = rejected || firstError;
    return;
  }
  if (firstWarning) {
    message.className = "builder-message visible warning";
    message.textContent = firstWarning;
    return;
  }
  if (validation.isValid) {
    const scanners = getAllSelectedScannerIds(profileDraft)
      .map((id) => findScanner(id)?.label)
      .filter(Boolean);
    message.className = "builder-message visible success";
    message.textContent = `Perfil valido: ${scanners.join(" + ")}`;
    return;
  }

  message.className = "builder-message";
  message.textContent = "";
}

function renderSavedProfiles() {
  if (!savedProfilesList) return;
  const activeId = loadSessionProfile()?.id;
  savedProfilesList.innerHTML = "";

  if (!savedProfiles.length) {
    savedProfilesList.innerHTML = `<p style="color:var(--t-dim);font-size:12px;padding:10px;">Aun no hay configuraciones guardadas.</p>`;
    return;
  }

  savedProfiles.forEach((profile) => {
    const item = document.createElement("article");
    item.className = "saved-profile-item" + (String(activeId) === String(profile.id) ? " active" : "");
    item.tabIndex = 0;
    item.setAttribute("role", "button");
    item.title = "Usar configuracion y elegir proyecto";
    item.innerHTML = `
      <div class="saved-profile-top">
        <div>
          <h3>${escapeHtml(profile.name)}</h3>
          <p>${escapeHtml(profile.description || "Perfil de analisis guardado.")}</p>
        </div>
        <div class="saved-profile-actions">
          <button type="button" class="btn" data-profile-use="${escapeHtml(profile.id)}">Usar</button>
        </div>
      </div>
      <div class="saved-profile-badges">
        ${profile.sast_enabled ? `<span>SAST: ${escapeHtml(profile.sast_tools || "semgrep")}</span>` : ""}
        ${profile.dast_enabled ? `<span>DAST: ${escapeHtml(profile.dast_tool || "zap")}</span>` : ""}
        ${profile.quality_enabled ? `<span>Quality: ${escapeHtml(profile.quality_tool || "auto")}</span>` : ""}
      </div>`;
    item.addEventListener("click", (event) => {
      if (event.target.closest("[data-profile-use]")) return;
      useSavedProfile(profile, true);
    });
    item.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        useSavedProfile(profile, true);
      }
    });
    item.querySelector("[data-profile-use]")?.addEventListener("click", () => useSavedProfile(profile, true));
    savedProfilesList.appendChild(item);
  });
}

function useSavedProfile(profile, openProjects = false) {
  const draft = profileToDraft(profile);
  const savedSessionProfile = saveSessionProfile(profile, draft);
  profileDraft = {
    ...draft,
    savedSessionProfile,
    applySavedProfileToNextProjects: true,
  };
  showFeedback(`Perfil activo: ${profile.name}`, "success");
  renderSavedProfiles();
  renderProfileBuilder();
  if (openProjects) onAddProject?.(profile);
}

function replaceDraft(nextDraft) {
  profileDraft = {
    ...nextDraft,
    savedSessionProfile: null,
  };
}

function slotLabel(slot) {
  return {
    sast: "SAST",
    dast: "DAST",
    sca: "SCA",
    quality: "Quality",
  }[slot] || slot;
}
