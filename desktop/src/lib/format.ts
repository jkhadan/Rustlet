// How numbers, times and states read in the UI (the CLI's conventions).

import type { ContainerState, ContainerSummary, PublishedPort } from "@/bindings";

/** 1536 → "1.5 KiB" (binary units, like `rustlet images`). */
export function bytes(n: number | null | undefined, digits = 1): string {
  if (n == null || !Number.isFinite(n)) return "–";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = Math.abs(n);
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  const text = u === 0 ? String(Math.round(v)) : v.toFixed(v >= 100 ? 0 : digits);
  return `${n < 0 ? "-" : ""}${text} ${units[u]}`;
}

/** Seconds → "3 seconds", "5 minutes", "2 hours", "4 days" (Docker's
 * HumanDuration). */
export function duration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 1) return "Less than a second";
  if (s === 1) return "1 second";
  if (s < 60) return `${s} seconds`;
  const m = Math.round(s / 60);
  if (m === 1) return "About a minute";
  if (m < 60) return `${m} minutes`;
  const h = Math.round(s / 3600);
  if (h === 1) return "About an hour";
  if (h < 48) return `${h} hours`;
  const d = Math.round(s / 86400);
  if (d < 14) return `${d} days`;
  if (d < 60) return `${Math.round(d / 7)} weeks`;
  if (d < 730) return `${Math.round(d / 30)} months`;
  return `${Math.round(d / 365)} years`;
}

/** Nanoseconds as Go writes a duration (`30s`, `1m30s`, `1h0m0s`,
 * `500ms`): the syntax `HEALTHCHECK --interval=` and compose files take,
 * in which healthchecks' settings arrive. */
export function goDuration(ns: number | null | undefined): string {
  if (ns == null || !Number.isFinite(ns)) return "–";
  let n = Math.abs(Math.round(ns));
  // Up to nine decimals, as Go prints them, without trailing zeros.
  const num = (v: number) => String(Number(v.toFixed(9)));
  let out: string;
  if (n === 0) out = "0s";
  else if (n < 1e3) out = `${n}ns`;
  else if (n < 1e6) out = `${num(n / 1e3)}µs`;
  else if (n < 1e9) out = `${num(n / 1e6)}ms`;
  else {
    const h = Math.floor(n / 3.6e12);
    n -= h * 3.6e12;
    const m = Math.floor(n / 6e10);
    n -= m * 6e10;
    const s = `${num(n / 1e9)}s`;
    out = h ? `${h}h${m}m${s}` : m ? `${m}m${s}` : s;
  }
  return ns < 0 ? `-${out}` : out;
}

/** An RFC 3339 time → "5 minutes ago". */
export function ago(time: string | null | undefined, now = Date.now()): string {
  const t = parseTime(time);
  if (t == null) return "–";
  return `${duration((now - t) / 1000)} ago`;
}

/** RFC 3339 → milliseconds. The daemon writes nanoseconds; engines need
 * not parse more than three fractional digits, so the rest goes. */
export function parseTime(time: string | null | undefined): number | null {
  if (!time) return null;
  const t = Date.parse(time.replace(/(\.\d{3})\d+/, "$1"));
  return Number.isNaN(t) ? null : t;
}

/** "Up 5 minutes", "Exited (0) 2 hours ago", as `rustlet ps` says it. */
export function statusText(state: ContainerState, now = Date.now()): string {
  const since = (t: string | null) => {
    const ms = parseTime(t);
    return ms == null ? "" : duration((now - ms) / 1000);
  };
  switch (state.status) {
    case "running":
      return `Up ${since(state.started_at)}`;
    case "paused":
      return `Up ${since(state.started_at)} (Paused)`;
    case "restarting":
      return `Restarting (${state.exit_code ?? 0}) ${since(state.finished_at)} ago`;
    case "exited":
      return `Exited (${state.exit_code ?? 0}) ${since(state.finished_at)} ago`;
    case "created":
      return "Created";
    case "removing":
      return "Removal in progress";
    case "dead":
      return "Dead";
  }
}

/** "0.0.0.0:8080->80/tcp". */
export function portText(p: PublishedPort): string {
  const host = p.host_ip.includes(":") ? `[${p.host_ip}]` : p.host_ip;
  return `${host}:${p.host_port}->${p.container_port}/${p.protocol}`;
}

/** The ports of a container, each mapping once (`0.0.0.0` and `[::]` of the
 * same port read as one, as `rustlet ps` shows them). */
export function portsText(ports: PublishedPort[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of ports) {
    const any = p.host_ip === "0.0.0.0" || p.host_ip === "::";
    const key = any ? `*:${p.host_port}->${p.container_port}/${p.protocol}` : portText(p);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(any ? `${p.host_port}->${p.container_port}/${p.protocol}` : portText(p));
  }
  return out;
}

export function shortId(id: string): string {
  return id.replace(/^sha256:/, "").slice(0, 12);
}

/** `docker.io/library/alpine:latest` → `alpine:latest`. */
export function imageName(name: string): string {
  return name.replace(/^docker\.io\/library\//, "").replace(/^docker\.io\//, "");
}

export function commandText(cmd: string[]): string {
  return cmd.map((a) => (/^[\w@%+=:,./-]+$/.test(a) ? a : `'${a.replace(/'/g, `'\\''`)}'`)).join(" ");
}

/** Splits a command line like a shell would (quotes, backslashes), for the
 * "command" field of the run dialog. */
export function splitCommand(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let has = false;
  let quote: '"' | "'" | null = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      // In double quotes a backslash quotes only what is special there
      // (POSIX: $, `, ", \ and a newline, which goes with it): before
      // anything else it stays, `"printf 'a\nb'"` is for printf to read.
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && i + 1 < line.length && '$`"\\\n'.includes(line[i + 1])) {
        if (line[++i] !== "\n") cur += line[i];
      } else cur += c;
    } else if (c === "'" || c === '"') {
      quote = c;
      has = true;
    } else if (c === "\\" && i + 1 < line.length) {
      cur += line[++i];
      has = true;
    } else if (/\s/.test(c)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += c;
    }
  }
  if (quote) throw new Error(`unclosed ${quote}`);
  if (has || cur) out.push(cur);
  return out;
}

export function isLive(c: Pick<ContainerSummary, "state">): boolean {
  return c.state.status === "running" || c.state.status === "paused";
}

/** "1 volume", "2 volumes". */
export function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

export function percent(n: number, digits = 1): string {
  return Number.isFinite(n) ? `${n.toFixed(digits)}%` : "–";
}
