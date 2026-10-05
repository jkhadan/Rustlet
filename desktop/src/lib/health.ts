// A container's health, as its healthcheck says it (`ContainerState.health`,
// kept by rustletd from each start: the verdict, the failures in a row and
// the last five checks): what the lists show beside its status, and what
// the Overview tab details.

import type { ContainerInspect, ContainerState, Health, HealthConfig, HealthResult, HealthStatus } from "@/bindings";

import { commandText, goDuration, parseTime } from "./format";

/** The verdict to show beside a container's status: its checks' while it
 * runs (as `rustlet ps` adds "(healthy)"), or is paused (checks wait, the
 * verdict stands). None without a healthcheck, nor for a container that
 * isn't running: what its last checks said is kept, but is about a run
 * that has ended. */
export function shownHealth(state: Pick<ContainerState, "status" | "health">): HealthStatus | null {
  if (state.status !== "running" && state.status !== "paused") return null;
  return state.health?.status ?? null;
}

/** How often to ask for a container again while it is being checked, in
 * milliseconds; false when it isn't (not running, or no healthcheck).
 * rustletd saves every check but announces only a change of verdict (a
 * check every few seconds as an event would flood every client), so a page
 * showing the checks would go stale between two verdicts: the one place
 * that polls. About as often as the container is checked, not oftener than
 * every second nor rarer than every five (the image's interval isn't in
 * the container's config, and the first checks come every `start_interval`,
 * 5 s by default); `refetchInterval` waits while the window isn't in
 * front, and a paused container isn't checked. */
export function healthPollMs(c: Pick<ContainerInspect, "state" | "config"> | undefined): number | false {
  if (!c || c.state.status !== "running" || !c.state.health) return false;
  const every = c.config.healthcheck?.interval;
  const ms = every != null && every > 0 ? every / 1e6 : 5_000;
  return Math.min(Math.max(ms, 1_000), 5_000);
}

/** The checks, newest first (the daemon keeps the last five, oldest
 * first). */
export function checksNewestFirst(h: Health): HealthResult[] {
  return h.log.slice().reverse();
}

/** How long a check took, in milliseconds. */
export function checkMillis(r: HealthResult): number | null {
  const start = parseTime(r.start);
  const end = parseTime(r.end);
  return start == null || end == null ? null : Math.max(0, end - start);
}

/** What a check's exit code means: 0 passed, -1 timed out or couldn't run
 * at all, anything else failed. */
export function checkOutcome(r: Pick<HealthResult, "exit_code">): "passed" | "failed" | "error" {
  return r.exit_code === 0 ? "passed" : r.exit_code === -1 ? "error" : "failed";
}

/** The check a container was created with: the image's (no test of its
 * own, or no `--health-*` option at all), none (`NONE`, `--no-healthcheck`),
 * a command line run by the image's shell (`CMD-SHELL`), or a program
 * with its arguments (`CMD`). */
export function describeTest(c: HealthConfig | null | undefined): { kind: "image" | "none" | "shell" | "exec"; command: string } {
  const test = c?.test ?? [];
  switch (test[0]) {
    case undefined:
      return { kind: "image", command: "" };
    case "NONE":
      return { kind: "none", command: "" };
    case "CMD-SHELL":
      return { kind: "shell", command: test.slice(1).join(" ") };
    case "CMD":
      return { kind: "exec", command: commandText(test.slice(1)) };
    default:
      // Docker reads a bare list as CMD's.
      return { kind: "exec", command: commandText(test) };
  }
}

/** The settings a container gave its healthcheck ("every 5s · timeout
 * 3s · 3 retries"); null when it gave none, and the image's (or the
 * defaults: every 30s, timeout 30s, 3 retries) apply. */
export function healthSettings(c: HealthConfig | null | undefined): string | null {
  if (!c) return null;
  const set = (v: number | null) => v != null && v > 0;
  const parts = [
    set(c.interval) && `every ${goDuration(c.interval)}`,
    set(c.timeout) && `timeout ${goDuration(c.timeout)}`,
    set(c.retries) && `${c.retries} ${c.retries === 1 ? "retry" : "retries"}`,
    set(c.start_period) && `start period ${goDuration(c.start_period)}`,
    set(c.start_interval) && `every ${goDuration(c.start_interval)} while starting`,
  ].filter((p): p is string => typeof p === "string");
  return parts.length ? parts.join(" · ") : null;
}
