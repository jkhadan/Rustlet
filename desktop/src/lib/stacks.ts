// Compose stacks as the Stacks view shows them (`stack_list`: the projects
// the daemon has containers of, found by their labels): a project's
// containers by service, and how much of it runs.

import type { Stack, StackContainer } from "./ipc";
import { shownHealth } from "./health";

export interface ServiceGroup {
  service: string;
  containers: StackContainer[];
}

/** A stack's containers by service, in the order they come (by service,
 * then number). */
export function servicesOf(stack: Stack): ServiceGroup[] {
  const groups: ServiceGroup[] = [];
  for (const c of stack.containers) {
    const last = groups.at(-1);
    if (last?.service === c.service) last.containers.push(c);
    else groups.push({ service: c.service, containers: [c] });
  }
  return groups;
}

/** `running`: every container runs; `partial`: some do; `stopped`: none. */
export type StackState = "running" | "partial" | "stopped";

export interface StackSummary {
  /** Live containers (running or paused). */
  running: number;
  total: number;
  state: StackState;
  /** Live containers whose healthcheck says unhealthy, or hasn't said yet. */
  unhealthy: number;
  starting: number;
}

export function stackSummary(stack: Stack): StackSummary {
  let running = 0;
  let unhealthy = 0;
  let starting = 0;
  for (const { container } of stack.containers) {
    const s = container.state.status;
    if (s === "running" || s === "paused") running++;
    const health = shownHealth(container.state);
    if (health === "unhealthy") unhealthy++;
    if (health === "starting") starting++;
  }
  const total = stack.containers.length;
  const state: StackState = total > 0 && running === total ? "running" : running > 0 ? "partial" : "stopped";
  return { running, total, state, unhealthy, starting };
}

/** "running 2/3", as `compose ls` counts. */
export function runningText(s: StackSummary): string {
  return `running ${s.running}/${s.total}`;
}

/** The files to bring the stack up again from: what its containers'
 * labels say it came from; null when they don't say (made by a tool that
 * doesn't label them so). */
export function upAgainFiles(stack: Stack): string[] | null {
  const files = stack.config_files.filter((f) => f.trim());
  return files.length ? files : null;
}

/** Stacks by name. */
export function sortStacks(stacks: Stack[]): Stack[] {
  return stacks.slice().sort((a, b) => a.name.localeCompare(b.name));
}
