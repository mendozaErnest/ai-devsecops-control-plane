// profile-builder-state.js - scan profile builder data and validation rules.
// Keep this module DOM-free so the future drag/drop UI can consume it directly.

export const PROFILE_BUILDER_STORAGE_KEY = "ai-devsecops.profileBuilder.session";

export const SCAN_SLOT_ORDER = ["sast", "dast", "sca", "quality"];

export const TECHNOLOGY_ITEMS = [
  {
    id: "python",
    label: "Python",
    kind: "language",
    apiTechnology: "python",
    iconLabel: "Py",
  },
  {
    id: "django",
    label: "Django",
    kind: "framework",
    parentTechnology: "python",
    apiTechnology: "python",
    iconLabel: "Dj",
  },
  {
    id: "flask",
    label: "Flask",
    kind: "framework",
    parentTechnology: "python",
    apiTechnology: "python",
    iconLabel: "Fl",
  },
  {
    id: "java",
    label: "Java",
    kind: "language",
    apiTechnology: "java",
    iconLabel: "Jv",
  },
  {
    id: "java-spring",
    label: "Spring",
    kind: "framework",
    parentTechnology: "java",
    apiTechnology: "java",
    iconLabel: "Sp",
  },
  {
    id: "typescript",
    label: "TypeScript",
    kind: "language",
    apiTechnology: "typescript",
    iconLabel: "Ts",
  },
  {
    id: "angular",
    label: "Angular",
    kind: "framework",
    parentTechnology: "typescript",
    apiTechnology: "angular",
    iconLabel: "A",
  },
  {
    id: "react",
    label: "React",
    kind: "framework",
    parentTechnology: "typescript",
    apiTechnology: "typescript",
    iconLabel: "Rx",
  },
];

export const SCANNER_ITEMS = [
  {
    id: "semgrep",
    label: "Semgrep",
    slot: "sast",
    persisted: true,
  },
  {
    id: "bandit",
    label: "Bandit",
    slot: "sast",
    persisted: true,
  },
  {
    id: "zap",
    label: "OWASP ZAP",
    slot: "dast",
    persisted: true,
    requires: ["targetUrl"],
  },
  {
    id: "pip-audit",
    label: "pip-audit",
    slot: "sca",
    persisted: false,
  },
  {
    id: "odc",
    label: "OWASP Dependency-Check",
    slot: "sca",
    persisted: false,
  },
  {
    id: "pylint",
    label: "Pylint",
    slot: "quality",
    persisted: true,
  },
  {
    id: "eslint",
    label: "ESLint",
    slot: "quality",
    persisted: true,
  },
  {
    id: "sonarqube",
    label: "SonarQube",
    slot: "quality",
    persisted: true,
  },
];

export const COMPATIBILITY_MATRIX = {
  semgrep: {
    technologies: ["python", "django", "flask", "angular", "typescript", "java", "java-spring"],
    message: "Semgrep tiene rulesets configurados para Python, TypeScript/Angular y Java.",
  },
  bandit: {
    technologies: ["python", "django", "flask"],
    message: "Bandit analiza codigo Python; no aplica a Java ni TypeScript.",
  },
  zap: {
    technologies: ["python", "django", "flask", "angular", "typescript", "java", "java-spring", "react"],
    requires: ["targetUrl"],
    message: "OWASP ZAP requiere una URL ejecutable del aplicativo.",
  },
  "pip-audit": {
    technologies: ["python", "django", "flask"],
    message: "pip-audit revisa dependencias Python.",
  },
  odc: {
    technologies: ["java", "java-spring"],
    message: "OWASP Dependency-Check se usara para dependencias Java en este builder.",
  },
  pylint: {
    technologies: ["python", "django", "flask"],
    message: "Pylint solo aplica a codigo Python.",
  },
  eslint: {
    technologies: ["angular", "typescript", "react"],
    message: "ESLint aplica a proyectos JavaScript/TypeScript.",
  },
  sonarqube: {
    technologies: ["python", "django", "flask", "angular", "typescript", "java", "java-spring"],
    message: "SonarQube esta integrado para Python, TypeScript/Angular y Java.",
  },
};

export function createEmptyProfileBuilderState() {
  return {
    selectedTechnologies: [],
    selectedScanners: {
      sast: [],
      dast: [],
      sca: [],
      quality: [],
    },
    profileName: "",
    targetUrl: "",
    validation: {
      isValid: false,
      errors: [],
      warnings: [],
      rejectedDrop: null,
    },
    savedSessionProfile: null,
    applySavedProfileToNextProjects: true,
  };
}

export function cloneProfileBuilderState(state) {
  return {
    ...state,
    selectedTechnologies: [...(state.selectedTechnologies || [])],
    selectedScanners: {
      sast: [...(state.selectedScanners?.sast || [])],
      dast: [...(state.selectedScanners?.dast || [])],
      sca: [...(state.selectedScanners?.sca || [])],
      quality: [...(state.selectedScanners?.quality || [])],
    },
    profileName: state.profileName || "",
    validation: {
      isValid: Boolean(state.validation?.isValid),
      errors: [...(state.validation?.errors || [])],
      warnings: [...(state.validation?.warnings || [])],
      rejectedDrop: state.validation?.rejectedDrop || null,
    },
    savedSessionProfile: state.savedSessionProfile || null,
    applySavedProfileToNextProjects: Boolean(state.applySavedProfileToNextProjects),
  };
}

export function findTechnology(id) {
  return TECHNOLOGY_ITEMS.find((item) => item.id === id) || null;
}

export function findScanner(id) {
  return SCANNER_ITEMS.find((item) => item.id === id) || null;
}

export function getAllSelectedScannerIds(state) {
  return SCAN_SLOT_ORDER.flatMap((slot) => state.selectedScanners?.[slot] || []);
}

export function canDropScannerOnTechnology(scannerId, technologyId, context = {}) {
  const scanner = findScanner(scannerId);
  const technology = findTechnology(technologyId);
  const rule = COMPATIBILITY_MATRIX[scannerId];

  if (!scanner) {
    return { ok: false, message: "Scanner desconocido." };
  }

  if (!technology) {
    return { ok: false, message: "Tecnologia desconocida." };
  }

  if (!rule || !rule.technologies.includes(technologyId)) {
    return {
      ok: false,
      message: `${scanner.label} no es compatible con ${technology.label}.`,
    };
  }

  // ZAP URL is supplied at scan time via the DAST input, not at profile-creation time.

  return { ok: true };
}

export function validateProfileDraft(state) {
  const errors = [];
  const warnings = [];
  const selectedTechnologies = state.selectedTechnologies || [];
  const selectedScanners = getAllSelectedScannerIds(state);
  const persistedScanners = selectedScanners.filter((scannerId) => findScanner(scannerId)?.persisted);

  if (selectedTechnologies.length === 0) {
    errors.push("Selecciona al menos una tecnologia.");
  }

  if (selectedScanners.length === 0) {
    errors.push("Selecciona al menos un scanner.");
  }

  if (selectedScanners.length > 0 && persistedScanners.length === 0) {
    errors.push("Selecciona al menos un scanner que pueda guardarse en ScanProfile.");
  }


  selectedScanners.forEach((scannerId) => {
    const scanner = findScanner(scannerId);
    const rule = COMPATIBILITY_MATRIX[scannerId];

    if (!scanner || !rule) {
      errors.push(`Scanner no soportado: ${scannerId}.`);
      return;
    }

    selectedTechnologies.forEach((technologyId) => {
      const result = canDropScannerOnTechnology(scannerId, technologyId, {
        targetUrl: state.targetUrl,
      });
      if (!result.ok) errors.push(result.message);
      if (result.warning) warnings.push(result.warning);
    });

    if (!scanner.persisted) {
      warnings.push(`${scanner.label} aun no se persiste en ScanProfile; se conserva en el borrador de UI.`);
    }
  });

  const uniqueErrors = [...new Set(errors)];
  const uniqueWarnings = [...new Set(warnings)];

  return {
    isValid: uniqueErrors.length === 0,
    errors: uniqueErrors,
    warnings: uniqueWarnings,
    rejectedDrop: null,
  };
}

export function applyValidation(state) {
  return {
    ...cloneProfileBuilderState(state),
    validation: validateProfileDraft(state),
  };
}

export function addTechnologyToDraft(state, technologyId) {
  if (!findTechnology(technologyId)) return applyRejectedDrop(state, technologyId, "Tecnologia desconocida.");
  const next = cloneProfileBuilderState(state);
  if (!next.selectedTechnologies.includes(technologyId)) {
    next.selectedTechnologies.push(technologyId);
  }
  return applyValidation(next);
}

export function removeTechnologyFromDraft(state, technologyId) {
  const next = cloneProfileBuilderState(state);
  next.selectedTechnologies = next.selectedTechnologies.filter((id) => id !== technologyId);
  return applyValidation(next);
}

export function addScannerToDraft(state, scannerId) {
  const scanner = findScanner(scannerId);
  if (!scanner) return applyRejectedDrop(state, scannerId, "Scanner desconocido.");

  const next = cloneProfileBuilderState(state);
  const slotItems = next.selectedScanners[scanner.slot] || [];

  for (const technologyId of next.selectedTechnologies) {
    const result = canDropScannerOnTechnology(scannerId, technologyId, {
      targetUrl: next.targetUrl,
    });
    if (!result.ok) return applyRejectedDrop(next, scannerId, result.message);
  }

  if (!slotItems.includes(scannerId)) {
    next.selectedScanners[scanner.slot] = [...slotItems, scannerId];
  }

  return applyValidation(next);
}

export function removeScannerFromDraft(state, scannerId) {
  const scanner = findScanner(scannerId);
  if (!scanner) return applyValidation(state);

  const next = cloneProfileBuilderState(state);
  next.selectedScanners[scanner.slot] = next.selectedScanners[scanner.slot].filter((id) => id !== scannerId);
  return applyValidation(next);
}

export function setDraftTargetUrl(state, targetUrl) {
  const next = cloneProfileBuilderState(state);
  next.targetUrl = targetUrl || "";
  return applyValidation(next);
}

export function applyRejectedDrop(state, itemId, message) {
  const next = cloneProfileBuilderState(state);
  next.validation = {
    ...validateProfileDraft(next),
    rejectedDrop: { itemId, message },
  };
  return next;
}

export function getPrimaryApiTechnology(state) {
  const firstTechnology = findTechnology(state.selectedTechnologies?.[0]);
  return firstTechnology?.apiTechnology || "python";
}

export function getApiTechnologiesFromState(state) {
  const values = (state.selectedTechnologies || [])
    .map((id) => findTechnology(id)?.apiTechnology)
    .filter(Boolean);
  return [...new Set(values)];
}

export function toScanProfilePayload(state) {
  const validated = applyValidation(state);
  if (!validated.validation.isValid) {
    throw new Error(validated.validation.errors[0] || "El perfil no es valido.");
  }

  const sast = validated.selectedScanners.sast || [];
  const quality = validated.selectedScanners.quality || [];
  const dast = validated.selectedScanners.dast || [];

  return {
    name: String(validated.profileName || "").trim() || buildProfileName(validated),
    description: "Perfil personalizado creado con el builder visual.",
    technologies: JSON.stringify(validated.selectedTechnologies || []),
    sast_enabled: sast.length > 0,
    sast_tools: resolveSastTools(sast),
    dast_enabled: dast.includes("zap"),
    dast_tool: dast.includes("zap") ? "zap" : null,
    quality_enabled: quality.length > 0,
    quality_tool: quality.length > 0 ? quality.join(",") : null,
  };
}

export function buildProfileName(state) {
  const techLabels = (state.selectedTechnologies || [])
    .map((id) => findTechnology(id)?.label)
    .filter(Boolean);
  const scannerLabels = getAllSelectedScannerIds(state)
    .map((id) => findScanner(id)?.label)
    .filter(Boolean);

  const techPart = techLabels.length ? techLabels.join(" + ") : "Custom";
  const scannerPart = scannerLabels.length ? scannerLabels.join(" + ") : "Security";

  return `${techPart} ${scannerPart}`;
}

export function profileToDraft(profile) {
  const next = createEmptyProfileBuilderState();
  next.profileName = profile?.name || "";
  next.selectedTechnologies = profileTechnologies(profile);
  next.selectedScanners = profileScanners(profile);
  const validated = applyValidation(next);
  return profile
    ? {
        ...validated,
        savedSessionProfile: {
          id: profile.id ?? null,
          name: profile.name || buildProfileName(validated),
          payload: profile,
          draft: cloneProfileBuilderState(validated),
          savedAt: new Date().toISOString(),
        },
      }
    : validated;
}

export function profileTechnologies(profile) {
  if (!profile) return [];

  try {
    const parsed = JSON.parse(profile.technologies || "[]");
    const valid = parsed.filter((id) => findTechnology(id));
    if (valid.length) return valid;
  } catch {
    // Fall through to conservative inference for older local profiles.
  }

  const name = String(profile.name || "").toLowerCase();
  if (name.includes("python")) return ["python", "django", "flask"];
  if (name.includes("angular")) return ["angular", "typescript"];
  if (name.includes("typescript") || name.includes("react")) return ["typescript", "react"];
  if (name.includes("java")) return ["java", "java-spring"];
  if (profile.sast_tools === "bandit" || profile.quality_tool === "pylint") return ["python"];
  if (profile.quality_tool === "eslint") return ["typescript", "angular", "react"];
  return TECHNOLOGY_ITEMS.map((item) => item.id);
}

export function profileScanners(profile) {
  const scanners = {
    sast: [],
    dast: [],
    sca: [],
    quality: [],
  };

  if (!profile) return scanners;

  if (profile.sast_enabled) {
    if (profile.sast_tools === "both") scanners.sast.push("semgrep", "bandit");
    else if (profile.sast_tools === "bandit") scanners.sast.push("bandit");
    else scanners.sast.push("semgrep");
  }

  if (profile.dast_enabled && profile.dast_tool === "zap") scanners.dast.push("zap");

  if (profile.quality_enabled && profile.quality_tool) {
    (profile.quality_tool).split(",").map((t) => t.trim()).filter(Boolean).forEach((tool) => {
      if (findScanner(tool)) scanners.quality.push(tool);
    });
  }

  return scanners;
}

export function isProjectCompatibleWithProfile(project, state) {
  const apiTechnologies = getApiTechnologiesFromState(state);
  if (!apiTechnologies.length) return true;
  return apiTechnologies.includes(String(project?.technology || "").trim().toLowerCase());
}

export function resolveSastTools(sastScannerIds) {
  const hasBandit = sastScannerIds.includes("bandit");
  const hasSemgrep = sastScannerIds.includes("semgrep");

  if (hasBandit && hasSemgrep) return "both";
  if (hasBandit) return "bandit";
  if (hasSemgrep) return "semgrep";
  return "semgrep";
}

function getSessionStorage() {
  return typeof window !== "undefined" ? window.sessionStorage : null;
}

export function saveSessionProfile(profile, state, storage = getSessionStorage()) {
  const draft = {
    ...cloneProfileBuilderState(state),
    savedSessionProfile: null,
  };
  const savedSessionProfile = {
    id: profile?.id ?? null,
    name: profile?.name || buildProfileName(state),
    payload: profile || null,
    draft,
    savedAt: new Date().toISOString(),
  };

  storage?.setItem(PROFILE_BUILDER_STORAGE_KEY, JSON.stringify(savedSessionProfile));
  return savedSessionProfile;
}

export function loadSessionProfile(storage = getSessionStorage()) {
  const raw = storage?.getItem(PROFILE_BUILDER_STORAGE_KEY);
  if (!raw) return null;

  try {
    return JSON.parse(raw);
  } catch {
    storage?.removeItem(PROFILE_BUILDER_STORAGE_KEY);
    return null;
  }
}
