# Handoff: Aegis — "Halo" design direction

## Overview
"Halo" is the chosen visual direction for the Aegis (AI DevSecOps Control Plane) dashboard.
It defines a **modern, minimal, futurist, and formal** aesthetic for a cybersecurity product:
deep neutral background, soft atmospheric blooms, asymmetric bento layout, generous numeric
hero, and one chromatic accent (electric mint) used sparingly to mark "live" / "AI" /
"active" states.

This handoff is the source of truth for **look, feel, motion, typography, color, and
component anatomy**. Recreate it inside the Aegis codebase using whatever framework is
already in place there (React, Vue, etc.). Do **not** ship the raw HTML.

## About the design files
The HTML in this bundle (`Halo — modern futurist.html`) is a **design reference**, not
production code. It uses inline `<style>` for clarity. Your job is to **recreate this
look** in the target codebase using its existing patterns:

- Translate the CSS custom properties in `tokens.css` into the codebase's token system
  (Tailwind theme, CSS modules, styled-components theme, etc.).
- Reuse existing layout primitives (cards, grids, buttons) and restyle them to match.
- Where the codebase has nothing comparable yet, build new components that follow the
  anatomy described in the "Components" section.

## Fidelity
**High-fidelity.** All measurements, colors, type sizes, weights, radii, shadows, and
motion timings in this document are final intent. Treat them as exact specs.

If a value is missing here, fall back to:
- 4px / 8px spacing grid
- 160ms ease-out for state transitions
- Geist for type, Geist Mono for monospaced data

---

## Visual principles — what makes this direction work

1. **Atmosphere over decoration.** Two soft radial blooms (mint top-right, violet
   bottom-left) live in a fixed `<div>` behind the app. They breathe slowly. No
   scanlines, no grid overlays, no border glow on every card.
2. **One accent.** Electric mint `#9EFFE0` is the **only** chromatic highlight. It marks
   live status, AI activity, the primary CTA, and "auto-fix" affordances. Everything
   else is neutral or severity-coded (warm coral/amber/gold/steel).
3. **Generous hierarchy.** The page has one undisputed hero (the active-findings number)
   sized at 156px. Everything else is sized down from that. Avoid having two competing
   hero elements on the same screen.
4. **Soft surfaces, soft borders.** Cards use 22px corner radius, a translucent panel
   color over the dark background, and a 1px border at 7% white. No hairline 1px borders
   on every element. No sharp 2px radii.
5. **Mono is a spice, not a base.** Use Geist Mono only for: file paths, rule IDs,
   commit hashes, branch names, and small numeric badges. Body copy, KPI numbers, and
   headings are sans-serif.
6. **Motion is atmospheric.** Bloom breathing (14–18s), AI orb pulse (3s), waveform bars
   (1.2s), live dots (1.8–2s). Avoid anything faster than 800ms for ambient motion. UI
   transitions (hover, focus) are 160ms ease-out.

---

## Design tokens

See `tokens.css` for the canonical CSS variable definitions. Summary:

### Colors

| Token            | Value                          | Usage                                            |
|------------------|--------------------------------|--------------------------------------------------|
| `--bg`           | `#07090C`                      | Page background (deep cool black)                |
| `--bg-warm`      | `#0A0D12`                      | Reserved — alt surface                           |
| `--surface`      | `rgba(255,255,255,0.025)`      | Lowest-elevation surface tint                    |
| `--surface-2`    | `rgba(255,255,255,0.04)`       | Inputs, chips, secondary buttons                 |
| `--surface-3`    | `rgba(255,255,255,0.06)`       | Hover state, nested panels                       |
| `--border`       | `rgba(255,255,255,0.07)`       | Default border on cards                          |
| `--border-2`     | `rgba(255,255,255,0.12)`       | Buttons, emphasized borders                      |
| `--t-hi`         | `#F5F7FA`                      | Primary text (headings, KPI values)              |
| `--t`            | `#C2C8D2`                      | Body text                                        |
| `--t-dim`        | `#7A818F`                      | Secondary, captions, meta                        |
| `--t-mute`       | `#4A5160`                      | Tertiary, tool names, separators                 |
| `--t-faint`      | `#2A2F3A`                      | Decorative / disabled                            |
| `--mint`         | `#9EFFE0`                      | Single chromatic accent — AI/live/active         |
| `--mint-dim`     | `#5AD7B5`                      | Mint at lower elevation (logo bg, glow base)     |
| `--mint-glow`    | `rgba(158,255,224,0.40)`       | Box-shadow / radial bloom                        |
| `--mint-soft`    | `rgba(158,255,224,0.08)`       | Tint backgrounds for "AI" pills/buttons          |
| `--crit`         | `#FF647D`                      | Critical severity (warm coral)                   |
| `--crit-soft`    | `rgba(255,100,125,0.10)`       | Critical tint                                    |
| `--high`         | `#FFA45C`                      | High severity (warm amber)                       |
| `--high-soft`    | `rgba(255,164,92,0.10)`        | High tint                                        |
| `--med`          | `#FFCF50`                      | Medium severity (gold)                           |
| `--med-soft`     | `rgba(255,207,80,0.10)`        | Medium tint                                      |
| `--low`          | `#94A3B8`                      | Low severity (cool steel)                        |
| `--low-soft`     | `rgba(148,163,184,0.10)`       | Low tint                                         |

### Typography

- **Display / UI**: `Geist`, fallback `system-ui, sans-serif`. Weights used: 300, 400, 500, 600, 700.
- **Mono**: `Geist Mono`, fallback `ui-monospace, monospace`. Weights: 400, 500.
- **Base body**: 14px / line-height 1.5 / weight 400.
- **`font-feature-settings`** on `html`: `"ss01", "ss03", "tnum"` — enables stylistic
  set 1 + 3 and tabular numerals globally.
- All numeric values (KPIs, counts, percentages) use `font-variant-numeric: tabular-nums`.

| Style          | Size  | Weight | Line height | Letter spacing |
|----------------|-------|--------|-------------|----------------|
| Hero figure    | 156px | 300    | 0.95        | -0.06em        |
| H1             | 36px  | 500    | 1.1         | -0.025em       |
| KPI number     | 44px  | 400    | 1           | -0.03em        |
| Orb stat       | 36px  | 500    | 1           | -0.02em        |
| AI stat        | 26px  | 500    | 1           | -0.02em        |
| Sev legend     | 22px  | 500    | 1           | -0.01em        |
| Card title h3  | 17px  | 500    | 1.3         | -0.01em        |
| Nav brand      | 15px  | 600    | —           | -0.01em        |
| Body / list    | 14px  | 400    | 1.5         | -0.005em       |
| Meta / caption | 12.5px| 400    | 1.4         | 0              |
| Mono inline    | 11px  | 400    | —           | 0              |

### Spacing

8px grid. Common values: 4, 6, 8, 10, 12, 14, 16, 18, 22, 24, 28, 32, 36.

### Radius

- Cards: **22px**
- Buttons / chips: **9–11px** (chips are pill `999px` when small)
- Inputs / small surfaces: **10px**
- Brand mark square: **9px**
- Tags / mono badges inside text: **5–7px**

### Shadows / glow

- Card surface: no shadow — separation comes from border + backdrop-filter.
- Primary button (mint): `0 4px 24px rgba(158,255,224,0.40), inset 0 1px 0 rgba(255,255,255,0.4)`
- Brand mark: same as above
- Mint hover lift: `0 6px 32px rgba(158,255,224,0.40)`
- Sev-mark critical glow: `0 0 8px rgba(255,100,125,0.10)`

### Backdrop blur

All translucent surfaces (nav, cards) use `backdrop-filter: blur(20px) saturate(140%)`.
Always include `-webkit-backdrop-filter` for Safari.

### Motion

| Element                | Animation                   | Duration | Easing             |
|------------------------|-----------------------------|----------|--------------------|
| Mint bloom (top-right) | `breathe` — scale + drift   | 14s      | `ease-in-out` loop |
| Violet bloom (btm-left)| `breathe2`                  | 18s      | `ease-in-out` loop |
| AI orb                 | scale 1 → 1.04              | 3s       | `ease-in-out` loop |
| Orb ring               | scale 1.25 → 1.5 + opacity  | 3s       | `ease-in-out` loop |
| Waveform bar           | height 6px → var(--h)       | 1.2s     | `ease-in-out`      |
| Live dot pulse         | opacity 1 → 0.45            | 1.8–2s   | `ease-in-out` loop |
| Radial ring            | full rotation               | 60s      | `linear` loop      |
| Auto-fix spinner       | rotate 360°                 | 0.8s     | `linear` loop      |
| Button hover lift      | `translateY(-1px)`          | 160ms    | (default)          |

---

## Layout / screens

This handoff covers **one screen**: `Overview` (the dashboard root).

### Page structure

```
<atmos>  fixed, z=0, two radial blooms + grain
<app>    relative, z=1, max-width 1480px, centered, padding 28/32/40
  ├─ <nav>             top bar (60px tall after padding)
  ├─ <head>            page title + actions
  └─ <bento>           3-column grid, 18px gap
        ├─ <hero>      spans 2 col × 2 row
        ├─ <ai-card>   1 col × 2 row
        ├─ <kpi>       1 col × 1 row (SLA breaches)
        ├─ <kpi>       1 col × 1 row (MTTR critical)
        └─ <findings>  spans 2 col × 1 row
```

`grid-template-columns: 1.4fr 1fr 1fr`. The hero card therefore is roughly 56% of grid
width.

### Sections in detail

#### 1. Top navigation
- 18px radius pill bar floating at the top.
- Background `rgba(13,16,22,0.55)` + `backdrop-filter`.
- Contents (left → right):
  1. **Brand mark**: 30×30px square, 9px radius, gradient mint, shield SVG inside.
     Box-shadow with mint glow.
  2. **Brand wordmark**: "Aegis", 15px, weight 600.
  3. **Repo chip**: `/` + repo name + `main` branch tag (mono, on `surface-2`).
  4. **Nav links** (Overview/Findings/Pipeline/Reports/Settings): 13px, 7×14 padding,
     9px radius. Active state uses `surface-3` background and `t-hi` color.
  5. **Spacer** (flex 1).
  6. **Status pill**: "Scanning · 3 of 4 adapters". Mint dot + mint text on `mint-soft`
     background, 999px radius.
  7. **Icon buttons** (search, notifications): 36×36, 10px radius, `surface-2`.
  8. **Avatar**: 36×36 gradient square, user initials, soft purple shadow.

#### 2. Page header
- Eyebrow: "Overview · Last scan 4 minutes ago", 13px `t-dim`.
- H1: 36px / weight 500. Uses a two-tone phrase: `"Your threat surface, "` in `t-hi`
  + `"in motion."` in `t-dim` (lighter weight 400 via inline `.lt` class).
- Right side: two buttons — secondary "Export" + primary "Run new scan".
- Primary button: mint background, dark text `#06231C`, glow shadow, lift on hover.

#### 3. Hero card (Active exposure)
- Grid: `1fr 320px`, gap 32px, padding 32/36.
- Decorative bloom inside the card: `radial-gradient` at -100/-100 (top-right corner),
  500×500, blurred 40px, opacity 0.6.
- **Left column**:
  - Eyebrow pill: "Live · Active exposure" — mint, mint-soft background, mint dot.
  - **Figure: "47"** — 156px, weight 300, gradient text from `#FFFFFF` (top, 30%) to
    `rgba(255,255,255,0.65)` (bottom). Background-clip: text.
  - Subcaption: "active findings across **8 modules** · **9 critical**"
    (strong = t-hi 500, crit = `--crit`).
  - **Severity bar**: 6px tall, fully rounded, four colored segments proportional to
    counts (Critical 19.1%, High 29.8%, Medium 38.3%, Low 12.8%).
  - **Severity legend**: 4 columns. Each cell = colored dot (with glow on critical)
    + label (`t-dim`) + number (22px, weight 500, `t-hi`).
- **Right column**: 300×300 radial visualizer.
  - Two soft outer rings (white at 4–5% opacity).
  - One 86-radius circle drawn 4 times with `stroke-dasharray`, each segment colored
    by severity, sized proportional to count. Total circumference / 47 = ~11.5 per
    finding.
  - One inner ring (mint at 15%).
  - The whole `<svg>` has class `radial-rotate` (60s linear rotation).
  - Center label: "Total" (11px caps, t-dim) + "47" (36px, t-hi) + "↑ +8 in 24h" (mint).

#### 4. AI remediation card
- Spans 2 rows on the right column.
- Decorative bloom: bottom-right, 280×280, mint, blur 40, opacity 0.7.
- **Header**: H3 "AI remediation" + right-aligned pill "Live · qwen2.5-coder".
- **Orb visualizer**: 140×140 sphere.
  - Inner background: two layered radial gradients — a small white highlight at
    35%/35% (specular), then mint-to-dim radial center-out, with an inner shadow at
    the bottom for volume.
  - Outer ring: 1px mint border at 30%, scaled to 1.25 in default state, animating
    to 1.5 with opacity 0.8 → 0.3.
  - Pulses subtly (1 → 1.04).
- **Waveform**: row of 20 vertical bars, 3px wide, mint, varying max-heights
  (--h custom prop). Staggered delays 0 → 1.1s.
- **Workers list**: 3 worker rows.
  - Row layout: name (mono-ish 500 t-hi) + target tag (mono, surface-3 chip) + status
    (right-aligned, mint or t-mute).
  - 3px progress bar with mint gradient fill.
  - "Idle" workers: 55% opacity, no bar.
- **Stats footer**: 2 columns separated by 14px top border.
  - "Patches today: 17"
  - "Accept rate: 74%"

#### 5. KPI cards
- Two equal cards (1×1 grid cells).
- Padding 22/24.
- Label (12.5px t-dim) → value row (n + delta chip) → caption → sparkline.
- **Delta chip**: 3×9px padding, 7px radius, font 11.5/500.
  - `.up`: mint-soft bg + mint text.
  - `.dn`: crit-soft bg + crit text.
  - `.warn`: high-soft bg + high text.
  - `.flat`: surface-3 bg + t-dim text.
- **Sparkline**: full width × 40px tall, absolute-positioned at the bottom of the card,
  opacity 0.6. Linear gradient area fill (color at 30% top opacity to 0 at bottom) +
  a 1.5px stroke polyline of the same color. Color matches the metric direction
  (positive = mint, negative = crit).

#### 6. Findings list (Active findings)
- Spans 2 columns.
- **Header bar**: H3 "Active findings" + caption "Sorted by severity, SLA" + right-aligned
  filter chips.
- **Filter chips**: pill (999px), surface-2 bg, 12px text. "On" state: t-hi bg, bg text.
  Each chip has a count badge.
- **Rows** (grid `28px 1fr auto auto`, gap 16, padding 14/26, border-bottom):
  - **Severity mark**: 4×32 vertical bar (colored, slight glow on critical).
  - **Body**:
    - Top row: rule name (14px / 500 / t-hi) + rule ID chip (mono on surface-3).
    - Bottom row: file path (mono, line number in mint) · tool · timestamp.
  - **SLA pill**: 4×9 padding, 7px radius, 11/500.
    - `brk` (overdue): crit-soft + crit.
    - `warn` (close): high-soft + high.
    - `ok`: surface-3 + t-dim.
  - **Action**: "Auto-fix" button (mint sparkle icon + label) — mint-soft bg, mint text,
    9px radius. OR "Fixing · worker-NN" with spinner if already in flight.
- Row hover: `surface-2` background.

---

## Components

### Button

```
.btn         neutral (surface-2 bg, t-hi text, border-2)
.btn.primary mint solid, dark text, glow shadow + inset highlight
.btn         hover: surface-3
.btn.primary hover: brighter mint + translateY(-1px) + bigger glow
```

Padding `10 18`, radius `11`, font 13/500. Always pair with a 12–14px lead icon when
the action is non-obvious.

### Chip / pill

```
.chip          surface-2 bg, border, 12px text, 5×11 padding, 999px radius
.chip.on       t-hi bg, bg text, t-hi border
.chip .n       count badge: 11px, surface-3 bg, 5px radius, tabular nums
```

### Card

```
background:
  linear-gradient(180deg, rgba(255,255,255,0.025), rgba(255,255,255,0.01)),
  rgba(13,16,22,0.55);
border: 1px solid rgba(255,255,255,0.07);
border-radius: 22px;
backdrop-filter: blur(20px) saturate(140%);
padding: 24px;          /* or 22/24 for KPIs, 32/36 for hero */
position: relative;
overflow: hidden;       /* required if the card has an internal bloom */
```

### Severity pill / mark

| Severity | Color     | Background tint           | Use            |
|----------|-----------|---------------------------|----------------|
| Critical | `#FF647D` | `rgba(255,100,125,0.10)`  | + 0 0 8px glow |
| High     | `#FFA45C` | `rgba(255,164,92,0.10)`   |                |
| Medium   | `#FFCF50` | `rgba(255,207,80,0.10)`   |                |
| Low      | `#94A3B8` | `rgba(148,163,184,0.10)`  |                |

Two forms:
- **Sev mark** (in findings list): 4×32 vertical pill of solid severity color.
- **Sev legend dot** (hero card): 7×7 circle, with `box-shadow: 0 0 6px <color>` on
  critical only.

### Mint accents — when (and when not) to use

**Use mint for:**
- Live status indicator + pulsing dot
- Primary CTA buttons
- AI / auto-fix actions
- "Active" navigation item background
- File-line numbers and code references (subtle)
- Stats trending in the *right* direction (e.g. MTTR going down)

**Don't use mint for:**
- Generic info / "neutral OK" — use `t-dim` or steel
- Severity (severity has its own warm palette)
- Borders or backgrounds at large area — keep mint reserved for points of focus

---

## Iconography

The reference uses simple line icons drawn inline as SVG:
- Shield (brand mark) — stroke 1.6, with checkmark inside
- Search magnifying glass, bell (notifications), upload arrow, play triangle
- Sparkle (4-point star) for AI/auto-fix actions

Match this style in production: 1.4–1.6 stroke, 16×16 viewBox, `stroke-linecap: round`,
`stroke-linejoin: round`. If the codebase already uses Lucide / Phosphor / Heroicons,
pick the closest matching outline icons at 16px and keep stroke weight consistent.

---

## State / data shape

The dashboard reads one summary object plus a list of findings:

```ts
type ScanSummary = {
  repo: string;
  branch: string;
  lastScanAgo: string;        // "4 minutes ago"
  adaptersOnline: number;     // 3
  adaptersTotal: number;      // 4
  totals: {
    findings: number;         // 47
    modules: number;          // 8
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  deltas: {
    slaBreaches: { value: number; delta: number };  // 13, +3
    mttrCriticalDays: { value: number; deltaPct: number }; // 2.4, -18
  };
  ai: {
    model: string;            // "qwen2.5-coder"
    patchesToday: number;     // 17
    acceptRate: number;       // 74
    workers: AIWorker[];
  };
};

type AIWorker = {
  id: string;                 // "worker-01"
  status: 'generating' | 'validating' | 'idle';
  target?: string;            // "B602"
  etaSec?: number;            // 8
  progress: number;           // 0–1
};

type Finding = {
  id: string;                 // "B602" | "CVE-2024-26130" | etc.
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;              // "OS shell-injection in subprocess call"
  path: string;               // "src/api/main.py"
  line: number;               // 142
  tool: string;               // "bandit"
  meta?: string;              // e.g. "CVSS 9.1", "3 occurrences"
  discoveredAt: string;       // ISO
  slaState: 'overdue' | 'warn' | 'ok';
  slaLabel: string;           // "1d overdue", "12h left"
  fixState?: { workerId: string };  // present if AI is currently fixing
};
```

---

## Files in this bundle

- `README.md` — this document.
- `tokens.css` — canonical CSS variable definitions, ready to drop in.
- `Halo — modern futurist.html` — the full reference mockup. Open it in a browser to
  see motion, hover states, and the final composition.

## Next steps for the implementing developer

1. Open `Halo — modern futurist.html` and walk the page once to internalize the look.
2. Drop `tokens.css` into the codebase's global styles (or translate it into your
   token system — Tailwind theme, etc.).
3. Wire the `ScanSummary` / `Finding` types to your existing data layer.
4. Build the page top-down: nav → header → hero → AI card → KPIs → findings.
5. Leave animations until layout + color is right; add motion last.
6. Use the bloom/atmospheric layer (`.atmos`) verbatim — it's the visual signature.

## Brand & assets
There is no production brand asset library yet for Aegis. The shield mark in the HTML
is a placeholder drawn in SVG — replace it with the real logo when one exists.
