// ── diff.js — diff view rendering (LCS-based and GitHub unified-diff) ────────

// ── Shared helpers (module-level) ────────────────────────────────────────────

/** Normalize line endings and split into an array of lines. */
function normalizeLines(text) {
  if (!text) return [];
  return text.replaceAll("\r\n", "\n").replaceAll("\r", "\n").split("\n");
}

/**
 * LCS-based line diff.
 * Returns an array of { type: "equal"|"insert"|"delete", left?, right? } operations.
 */
function computeDiff(linesA, linesB) {
  const m = linesA.length, n = linesB.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = linesA[i - 1] === linesB[j - 1]
        ? dp[i - 1][j - 1] + 1
        : Math.max(dp[i - 1][j], dp[i][j - 1]);
  const ops = [];
  let i = m, j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && linesA[i - 1] === linesB[j - 1]) {
      ops.push({ type: "equal", left: linesA[i - 1], right: linesB[j - 1] }); i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      ops.push({ type: "insert", right: linesB[j - 1] }); j--;
    } else {
      ops.push({ type: "delete", left: linesA[i - 1] }); i--;
    }
  }
  return ops.reverse();
}

export function buildDiffToolbar(badgeText, badgeColor) {
  const toolbar = document.createElement("div");
  toolbar.style.cssText =
    "display:flex;align-items:center;justify-content:space-between;padding:5px 12px;" +
    "background:#161b22;border-bottom:1px solid #21262d;flex-shrink:0;";
  toolbar.innerHTML =
    '<span style="font-size:.7rem;font-weight:700;color:#f85149;text-transform:uppercase;letter-spacing:.08em;">− Antes</span>' +
    `<span style="color:${badgeColor || "#6e7681"};font-size:.7rem;letter-spacing:.04em;white-space:nowrap;">${badgeText || ""}</span>` +
    '<span style="font-size:.7rem;font-weight:700;color:#3fb950;text-transform:uppercase;letter-spacing:.08em;">+ Después</span>';
  return toolbar;
}

// LCS-based diff between two sets of lines (AI proposal view)
export function renderDiffView(diffViewEl, snippetCode, proposedCode, fileData) {
  diffViewEl.innerHTML = "";

  const safeSnippet = (snippetCode || "").trim();
  const safeProposed = (proposedCode || "").trim();

  if (!safeSnippet && !safeProposed) {
    diffViewEl.innerHTML = `<div style="padding:20px;color:var(--muted);font-size:.82rem;">
      Sin código disponible para mostrar diff.</div>`;
    return;
  }

  const effectiveSnippet = safeSnippet ? String(snippetCode) : "";
  const effectiveProposed = safeProposed ? String(proposedCode) : "";
  const forceReplacement = Boolean(safeSnippet && safeProposed && safeSnippet === safeProposed);

  const snippetLines = normalizeLines(effectiveSnippet);
  const proposedLines = normalizeLines(effectiveProposed);

  function buildReplacementOps(linesA, linesB) {
    if (forceReplacement) {
      return [
        ...linesA.map((line) => ({ type: "delete", left: line })),
        ...linesB.map((line) => ({ type: "insert", right: line })),
      ];
    }

    return computeDiff(linesA, linesB);
  }

  function buildSideRows(ops) {
    const leftRows = [], rightRows = [];
    ops.forEach((op) => {
      if (op.type === "equal") {
        leftRows.push({ line: op.left, type: "equal" });
        rightRows.push({ line: op.right, type: "equal" });
      } else if (op.type === "delete") {
        leftRows.push({ line: op.left, type: "delete" });
        rightRows.push({ line: "", type: "pad" });
      } else {
        leftRows.push({ line: "", type: "pad" });
        rightRows.push({ line: op.right, type: "insert" });
      }
    });
    return [leftRows, rightRows];
  }

  const [leftDiff, rightDiff] = buildSideRows(buildReplacementOps(snippetLines, proposedLines));

  const CONTEXT = 20;
  let allLeftRows, allRightRows, startLine;

  if (fileData && fileData.content) {
    const fileLines = fileData.content.split("\n");
    const sStart = Math.max(0, (fileData.line_number || 1) - 1);
    const affectedLineCount = Math.max(snippetLines.length, safeProposed ? 1 : 0);
    const sEnd = sStart + affectedLineCount;
    const ctxFrom = Math.max(0, sStart - CONTEXT);
    const ctxTo = Math.min(fileLines.length, sEnd + CONTEXT);

    const before = fileLines.slice(ctxFrom, sStart).map((l) => ({ line: l, type: "equal" }));
    const after  = fileLines.slice(sEnd,   ctxTo).map((l) => ({ line: l, type: "equal" }));
    const gapB = ctxFrom > 0                   ? [{ line: "···", type: "gap" }] : [];
    const gapA = ctxTo < fileLines.length       ? [{ line: "···", type: "gap" }] : [];

    // ANTES uses real file lines for the affected region, not stale/empty snippets.
    const originalRegionLines = fileLines.slice(sStart, sEnd);
    const regionSourceLines = originalRegionLines.length ? originalRegionLines : snippetLines;
    const [regionLeftDiff, regionRightDiff] = buildSideRows(
      buildReplacementOps(regionSourceLines, proposedLines)
    );

    allLeftRows  = [...gapB, ...before, ...regionLeftDiff,  ...after, ...gapA];
    allRightRows = [...gapB, ...before, ...regionRightDiff, ...after, ...gapA];
    startLine = ctxFrom + 1;
  } else {
    // Fallback when no file content is available: show LCS diff for both columns
    const missingSnippet = !safeSnippet && safeProposed
      ? [{ line: "Snippet original no disponible", type: "gap" }]
      : [];
    allLeftRows  = [{ line: "···", type: "gap" }, ...missingSnippet, ...leftDiff,  { line: "···", type: "gap" }];
    allRightRows = [{ line: "···", type: "gap" }, ...rightDiff, { line: "···", type: "gap" }];
    startLine = 1;
  }

  const STYLE = {
    equal:  { rowBg: "transparent", numBg: "#0d1117", codeFg: "#c9d1d9", numFg: "#484f58", signCh: " " },
    delete: { rowBg: "#1c1010",     numBg: "#1c1010", codeFg: "#cd7070", numFg: "#5e2828", signCh: "−" },
    insert: { rowBg: "#0f1a0e",     numBg: "#0f1a0e", codeFg: "#5ca870", numFg: "#1a3a1a", signCh: "+" },
    gap:    { rowBg: "#161b22",     numBg: "#161b22", codeFg: "#484f58", numFg: "#30363d", signCh: "" },
    pad:    { rowBg: "#161b22",     numBg: "#161b22", codeFg: "transparent", numFg: "transparent", signCh: "" },
    // "hi" = real file line in ANTES that is the affected/vulnerable region (never from Ollama text)
    hi:     { rowBg: "#101828",     numBg: "#0d1117", codeFg: "#c9d1d9", numFg: "#3875b8", signCh: "·" },
  };

  function buildColumn(rows, startLineNum, borderColor) {
    const col = document.createElement("div");
    col.style.cssText =
      `flex:1;min-width:0;min-height:0;display:flex;flex-direction:column;` +
      `border-right:1px solid ${borderColor};overflow:hidden;`;

    const scroll = document.createElement("div");
    scroll.style.cssText = "flex:1;min-height:0;overflow-x:auto;overflow-y:auto;background:#0d1117;";

    const table = document.createElement("table");
    table.style.cssText =
      "border-collapse:collapse;min-width:100%;width:max-content;" +
      "font-family:'Courier New',monospace;font-size:.8rem;line-height:1.7;";

    let lineNum = startLineNum;
    rows.forEach(({ line, type }) => {
      const s = STYLE[type] || STYLE.equal;
      const isPad = type === "pad";
      const isGap = type === "gap";
      const showNum = !isPad && !isGap;

      const tr = document.createElement("tr");
      tr.style.backgroundColor = s.rowBg;

      const tdNum = document.createElement("td");
      tdNum.style.cssText =
        `min-width:42px;padding:0 8px;color:${s.numFg};font-size:.7rem;user-select:none;` +
        `text-align:right;white-space:nowrap;position:sticky;left:0;background:${s.numBg};` +
        `z-index:1;border-right:1px solid rgba(255,255,255,0.04);`;
      tdNum.textContent = showNum ? lineNum : "";

      const tdSign = document.createElement("td");
      let colSignColor = "#484f58";
      if (type === "delete") colSignColor = "#cd7070";
      else if (type === "insert") colSignColor = "#5ca870";
      tdSign.style.cssText =
        `min-width:18px;padding:0 4px;color:${colSignColor};font-weight:700;white-space:nowrap;`;
      tdSign.textContent = s.signCh;

      const tdCode = document.createElement("td");
      tdCode.style.cssText = `color:${s.codeFg};padding:0 16px 0 2px;white-space:pre;`;
      let colCodeText = line;
      if (isGap) colCodeText = "···";
      else if (isPad) colCodeText = "";
      tdCode.textContent = colCodeText;

      tr.append(tdNum, tdSign, tdCode);
      table.appendChild(tr);

      if (showNum) lineNum++;
    });

    scroll.appendChild(table);
    col.appendChild(scroll);
    return col;
  }

  const leftCol = buildColumn(allLeftRows, startLine, "#3a1515");
  const rightCol = buildColumn(allRightRows, startLine, "transparent");

  diffViewEl.style.flexDirection = "column";
  const toolbar = buildDiffToolbar("⚠ Propuesta AI", "#b8860b");
  const columnsRow = document.createElement("div");
  columnsRow.style.cssText =
    "display:flex;align-items:stretch;flex:1;min-height:0;overflow:hidden;";
  columnsRow.appendChild(leftCol);
  columnsRow.appendChild(rightCol);
  diffViewEl.appendChild(toolbar);
  diffViewEl.appendChild(columnsRow);
}

/**
 * Render a diff between full file contents (original vs patched).
 * Used for the "Propuesta AI" panel when the server can compute the exact change.
 * Falls back to renderDiffView when preview data is unavailable.
 *
 * @param {HTMLElement} diffViewEl
 * @param {string} originalContent  - full original file text
 * @param {string} patchedContent   - full patched file text
 */
export function renderPreviewDiff(diffViewEl, originalContent, patchedContent) {
  diffViewEl.innerHTML = "";

  const origLines = normalizeLines(originalContent);
  const patchLines = normalizeLines(patchedContent);
  const ops = computeDiff(origLines, patchLines);

  // Collapse context: keep at most CONTEXT equal lines around changes
  const CONTEXT = 5;
  const changeIdx = ops.reduce((acc, op, i) => {
    if (op.type !== "equal") { acc.push(i); }
    return acc;
  }, []);

  // Determine which indices to show
  const visible = new Set();
  changeIdx.forEach((ci) => {
    for (let k = Math.max(0, ci - CONTEXT); k <= Math.min(ops.length - 1, ci + CONTEXT); k++) {
      visible.add(k);
    }
  });

  // Build side rows with gap markers between collapsed regions
  const leftRows = [], rightRows = [];
  let prevVisible = true;
  ops.forEach((op, idx) => {
    if (!visible.has(idx)) {
      if (prevVisible) {
        leftRows.push({ line: "···", type: "gap" });
        rightRows.push({ line: "···", type: "gap" });
      }
      prevVisible = false;
      return;
    }
    prevVisible = true;
    if (op.type === "equal") {
      leftRows.push({ line: op.left, type: "equal" });
      rightRows.push({ line: op.right, type: "equal" });
    } else if (op.type === "delete") {
      leftRows.push({ line: op.left, type: "delete" });
      rightRows.push({ line: "", type: "pad" });
    } else {
      leftRows.push({ line: "", type: "pad" });
      rightRows.push({ line: op.right, type: "insert" });
    }
  });
  if (!prevVisible) {
    leftRows.push({ line: "···", type: "gap" });
    rightRows.push({ line: "···", type: "gap" });
  }

  const STYLE = {
    equal:  { rowBg: "transparent", numBg: "#0d1117", codeFg: "#c9d1d9", numFg: "#484f58", signCh: " " },
    delete: { rowBg: "#1c1010",     numBg: "#1c1010", codeFg: "#cd7070", numFg: "#5e2828", signCh: "−" },
    insert: { rowBg: "#0f1a0e",     numBg: "#0f1a0e", codeFg: "#5ca870", numFg: "#1a3a1a", signCh: "+" },
    gap:    { rowBg: "#161b22",     numBg: "#161b22", codeFg: "#484f58", numFg: "#30363d", signCh: "" },
    pad:    { rowBg: "#161b22",     numBg: "#161b22", codeFg: "transparent", numFg: "transparent", signCh: "" },
  };

  function buildCol(rows, borderColor) {
    const col = document.createElement("div");
    col.style.cssText =
      `flex:1;min-width:0;min-height:0;display:flex;flex-direction:column;` +
      `border-right:1px solid ${borderColor};overflow:hidden;`;
    const scroll = document.createElement("div");
    scroll.style.cssText = "flex:1;min-height:0;overflow-x:auto;overflow-y:auto;background:#0d1117;";
    const table = document.createElement("table");
    table.style.cssText =
      "border-collapse:collapse;min-width:100%;width:max-content;" +
      "font-family:'Courier New',monospace;font-size:.8rem;line-height:1.7;";

    let lineNum = 1;
    rows.forEach(({ line, type }) => {
      const s = STYLE[type] || STYLE.equal;
      const isGap = type === "gap";
      const isPad = type === "pad";
      const showNum = !isGap && !isPad;

      const tr = document.createElement("tr");
      tr.style.backgroundColor = s.rowBg;

      const tdNum = document.createElement("td");
      tdNum.style.cssText =
        `min-width:42px;padding:0 8px;color:${s.numFg};font-size:.7rem;user-select:none;` +
        `text-align:right;white-space:nowrap;position:sticky;left:0;background:${s.numBg};` +
        `z-index:1;border-right:1px solid rgba(255,255,255,0.04);`;
      tdNum.textContent = showNum ? lineNum : "";

      const tdSign = document.createElement("td");
      let signColor = "#484f58";
      if (type === "delete") signColor = "#cd7070";
      else if (type === "insert") signColor = "#5ca870";
      tdSign.style.cssText =
        `min-width:18px;padding:0 4px;color:${signColor};font-weight:700;white-space:nowrap;`;
      tdSign.textContent = s.signCh;

      const tdCode = document.createElement("td");
      tdCode.style.cssText = `color:${s.codeFg};padding:0 16px 0 2px;white-space:pre;`;
      let codeText = line;
      if (isGap) codeText = "···";
      else if (isPad) codeText = "";
      tdCode.textContent = codeText;

      tr.append(tdNum, tdSign, tdCode);
      table.appendChild(tr);
      if (showNum) lineNum++;
    });

    scroll.appendChild(table);
    col.appendChild(scroll);
    return col;
  }

  diffViewEl.style.flexDirection = "column";
  const toolbar = buildDiffToolbar("✓ Vista previa exacta del PR", "#3fb950");
  const columnsRow = document.createElement("div");
  columnsRow.style.cssText =
    "display:flex;align-items:stretch;flex:1;min-height:0;overflow:hidden;";
  columnsRow.appendChild(buildCol(leftRows, "#3a1515"));
  columnsRow.appendChild(buildCol(rightRows, "transparent"));
  diffViewEl.appendChild(toolbar);
  diffViewEl.appendChild(columnsRow);
}

function parseHunks(diff) {
  const dlines = diff.split("\n");
  const hs = [];
  let cur = null;
  for (let index = 0; index < dlines.length; index++) {
    const raw = dlines[index];
    if (index === dlines.length - 1 && raw === "") continue;
    if (
      raw.startsWith("diff --git") || raw.startsWith("index ") ||
      raw.startsWith("--- ") || raw.startsWith("+++ ") ||
      raw.startsWith("\\ No newline")
    ) continue;
    if (raw.startsWith("@@")) {
      const m = raw.match(/@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
      if (m) {
        cur = {
          oldStart: +m[1],
          oldCount: m[2] ? +m[2] : 1,
          newStart: +m[3],
          newCount: m[4] ? +m[4] : 1,
          header: raw,
          changes: [],
        };
        hs.push(cur);
      }
      continue;
    }
    if (!cur) continue;
    if (raw.startsWith("-"))      cur.changes.push({ type: "del", content: raw.slice(1) });
    else if (raw.startsWith("+")) cur.changes.push({ type: "ins", content: raw.slice(1) });
    else                          cur.changes.push({ type: "eq",  content: raw.startsWith(" ") ? raw.slice(1) : raw });
  }
  return hs;
}

function buildRowsFromHunks(hunks) {
  const leftRows = [];
  const rightRows = [];

  hunks.forEach((hunk, hunkIndex) => {
    if (hunkIndex > 0) {
      leftRows.push({ line: "", lineNum: "", t: "spacer" });
      rightRows.push({ line: "", lineNum: "", t: "spacer" });
    }

    leftRows.push({ line: hunk.header, lineNum: "", t: "hunk" });
    rightRows.push({ line: hunk.header, lineNum: "", t: "hunk" });

    let oldLine = hunk.oldStart;
    let newLine = hunk.newStart;

    for (const change of hunk.changes) {
      if (change.type === "eq") {
        leftRows.push({ line: change.content, lineNum: oldLine, t: "eq" });
        rightRows.push({ line: change.content, lineNum: newLine, t: "eq" });
        oldLine++;
        newLine++;
      } else if (change.type === "del") {
        leftRows.push({ line: change.content, lineNum: oldLine, t: "del" });
        rightRows.push({ line: "", lineNum: "", t: "pad" });
        oldLine++;
      } else if (change.type === "ins") {
        leftRows.push({ line: "", lineNum: "", t: "pad" });
        rightRows.push({ line: change.content, lineNum: newLine, t: "ins" });
        newLine++;
      }
    }
  });

  return { leftRows, rightRows };
}

function buildPanel(rows, borderColor) {
  const panel = document.createElement("div");
  panel.style.cssText =
    `min-width:0;min-height:0;overflow-y:auto;overflow-x:auto;background:#0d1117;` +
    `border-right:1px solid ${borderColor};`;
  const T = {
    eq:     { rb: "transparent", nb: "#0d1117", cf: "#c9d1d9", nf: "#484f58", sf: "#484f58", sign: " " },
    del:    { rb: "#3d1a1a",     nb: "#3d1a1a", cf: "#ff9090", nf: "#ff6b6b", sf: "#ff9090", sign: "-" },
    ins:    { rb: "#1a3d1a",     nb: "#1a3d1a", cf: "#90ff90", nf: "#6bff6b", sf: "#90ff90", sign: "+" },
    hunk:   { rb: "#0d1b2d",     nb: "#0d1b2d", cf: "#79c0ff", nf: "#58a6ff", sf: "#58a6ff", sign: "" },
    pad:    { rb: "#10151d",     nb: "#10151d", cf: "transparent", nf: "transparent", sf: "transparent", sign: "" },
    spacer: { rb: "#0d1117",     nb: "#0d1117", cf: "#484f58", nf: "transparent", sf: "transparent", sign: "" },
  };
  const tbl = document.createElement("table");
  tbl.style.cssText =
    'border-collapse:collapse;min-width:100%;width:max-content;font-family:"Courier New",monospace;font-size:.8rem;line-height:1.7;';
  rows.forEach(({ line, lineNum, t }) => {
    const s = T[t] || T.eq;
    const tr = document.createElement("tr");
    tr.style.backgroundColor = s.rb;
    const tdN = document.createElement("td");
    tdN.style.cssText =
      `min-width:42px;padding:0 8px;color:${s.nf};font-size:.7rem;user-select:none;` +
      `text-align:right;white-space:nowrap;position:sticky;left:0;background:${s.nb};` +
      `z-index:1;border-right:1px solid rgba(255,255,255,.04);`;
    tdN.textContent = lineNum;
    const tdS = document.createElement("td");
    tdS.style.cssText =
      `min-width:18px;padding:0 4px;color:${s.sf};font-weight:700;white-space:nowrap;`;
    tdS.textContent = s.sign;
    const tdC = document.createElement("td");
    tdC.style.cssText = `color:${s.cf};padding:0 16px 0 8px;white-space:pre;`;
    tdC.textContent = line;
    tr.append(tdN, tdS, tdC);
    tbl.appendChild(tr);
  });
  panel.appendChild(tbl);
  return panel;
}

// GitHub unified-diff renderer
// fileLines is kept for backwards compatibility; the raw GitHub unified diff is authoritative.
export function renderGitHubDiff(diffViewEl, rawDiff, _fileLines) {
  const hunks = parseHunks(rawDiff);
  if (!hunks.length) return;

  diffViewEl.innerHTML = "";
  diffViewEl.style.flexDirection = "column";

  const hdr = document.createElement("div");
  hdr.style.cssText =
    "display:flex;align-items:center;justify-content:space-between;padding:5px 12px;" +
    "background:#161b22;border-bottom:1px solid #21262d;flex-shrink:0;";
  hdr.innerHTML =
    '<span style="font-size:.7rem;font-weight:700;color:#f85149;text-transform:uppercase;letter-spacing:.08em;">— Antes</span>' +
    '<span style="color:#3fb950;font-size:.7rem;letter-spacing:.04em;white-space:nowrap;">✓ Diff real del PR en GitHub</span>' +
    '<span style="font-size:.7rem;font-weight:700;color:#3fb950;text-transform:uppercase;letter-spacing:.08em;">+ Después</span>';

  const panelsRow = document.createElement("div");
  panelsRow.style.cssText = "display:grid;grid-template-columns:1fr 1fr;flex:1;min-height:0;overflow:hidden;";

  const { leftRows, rightRows } = buildRowsFromHunks(hunks);
  const firstChangedIndex = Math.max(
    0,
    leftRows.findIndex((row, index) => row.t === "del" || rightRows[index]?.t === "ins") - 4
  );
  const panelAntes = buildPanel(leftRows, "#3a1515");
  const panelDespues = buildPanel(rightRows, "transparent");
  panelsRow.append(panelAntes, panelDespues);

  requestAnimationFrame(() => {
    const top = firstChangedIndex * 22;
    panelAntes.scrollTop = top;
    panelDespues.scrollTop = top;
  });

  let syncing = false;
  panelAntes.addEventListener("scroll", () => {
    if (syncing) return;
    syncing = true;
    panelDespues.scrollTop = panelAntes.scrollTop;
    panelDespues.scrollLeft = panelAntes.scrollLeft;
    requestAnimationFrame(() => { syncing = false; });
  });
  panelDespues.addEventListener("scroll", () => {
    if (syncing) return;
    syncing = true;
    panelAntes.scrollTop = panelDespues.scrollTop;
    panelAntes.scrollLeft = panelDespues.scrollLeft;
    requestAnimationFrame(() => { syncing = false; });
  });

  diffViewEl.appendChild(hdr);
  diffViewEl.appendChild(panelsRow);
}
