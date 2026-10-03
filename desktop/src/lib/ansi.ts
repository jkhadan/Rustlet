// Colours in container logs. Programs that think they write to a terminal
// colour their output with SGR escape sequences (`ESC [ 31 m` … `ESC [ 0 m`).
// The logs view turns those into styled spans and drops every other
// escape sequence (cursor movement and the like mean nothing in a list of
// lines).

export interface Span {
  text: string;
  fg?: string;
  bg?: string;
  bold?: boolean;
  dim?: boolean;
  italic?: boolean;
  underline?: boolean;
}

/** The 16 basic colours, as CSS variables a theme can set (with fallbacks
 * that read on both light and dark backgrounds). */
const BASIC = [
  "#4b5563", "#dc2626", "#16a34a", "#ca8a04", "#2563eb", "#c026d3", "#0891b2", "#9ca3af",
  "#6b7280", "#ef4444", "#22c55e", "#eab308", "#3b82f6", "#d946ef", "#06b6d4", "#e5e7eb",
];

/** xterm's 256-colour palette entry `n`. */
export function color256(n: number): string {
  if (n < 16) return BASIC[n];
  if (n < 232) {
    const i = n - 16;
    const level = (v: number) => (v === 0 ? 0 : 55 + v * 40);
    const r = level(Math.floor(i / 36));
    const g = level(Math.floor(i / 6) % 6);
    const b = level(i % 6);
    return `rgb(${r}, ${g}, ${b})`;
  }
  const grey = 8 + (n - 232) * 10;
  return `rgb(${grey}, ${grey}, ${grey})`;
}

// CSI sequences (ESC [ … final byte) and OSC sequences (ESC ] … BEL/ST),
// and lone two-character escapes.
// eslint-disable-next-line no-control-regex
const ESCAPE = /\x1b\[([0-9;:?]*)([@-~])|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]/g;

type Style = Omit<Span, "text">;

function applySgr(params: string, style: Style): Style {
  const codes = params === "" ? [0] : params.split(/[;:]/).map((p) => (p === "" ? 0 : Number(p)));
  let s = { ...style };
  for (let i = 0; i < codes.length; i++) {
    const c = codes[i];
    if (c === 0) s = {};
    else if (c === 1) s.bold = true;
    else if (c === 2) s.dim = true;
    else if (c === 3) s.italic = true;
    else if (c === 4) s.underline = true;
    else if (c === 22) s.bold = s.dim = undefined;
    else if (c === 23) s.italic = undefined;
    else if (c === 24) s.underline = undefined;
    else if (c >= 30 && c <= 37) s.fg = BASIC[c - 30];
    else if (c >= 90 && c <= 97) s.fg = BASIC[c - 90 + 8];
    else if (c === 39) s.fg = undefined;
    else if (c >= 40 && c <= 47) s.bg = BASIC[c - 40];
    else if (c >= 100 && c <= 107) s.bg = BASIC[c - 100 + 8];
    else if (c === 49) s.bg = undefined;
    else if (c === 38 || c === 48) {
      const key = c === 38 ? "fg" : "bg";
      if (codes[i + 1] === 5 && codes[i + 2] !== undefined) {
        s[key] = color256(codes[i + 2]);
        i += 2;
      } else if (codes[i + 1] === 2 && codes[i + 4] !== undefined) {
        s[key] = `rgb(${codes[i + 2]}, ${codes[i + 3]}, ${codes[i + 4]})`;
        i += 4;
      }
    }
  }
  return s;
}

/** A line of output as styled spans; `state` carries the style across
 * lines (a colour set on one line and reset on a later one). */
export function parseAnsi(line: string, state: { style: Style } = { style: {} }): Span[] {
  const spans: Span[] = [];
  let at = 0;
  const push = (text: string) => {
    if (text) spans.push({ text, ...state.style });
  };
  for (const m of line.matchAll(ESCAPE)) {
    push(line.slice(at, m.index));
    at = (m.index ?? 0) + m[0].length;
    if (m[2] === "m") state.style = applySgr(m[1] ?? "", state.style);
  }
  push(line.slice(at));
  return spans;
}

/** The text without any escape sequence. */
export function stripAnsi(line: string): string {
  return line.replace(ESCAPE, "");
}
