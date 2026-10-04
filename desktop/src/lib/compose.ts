// A `compose up`'s progress, folded from its messages (`ComposeProgress`,
// src-tauri/src/compose.rs): each network, volume, container and image
// with the last thing that happened to it (as `docker compose up` prints a
// line per resource and redraws it), the builds and pulls of services'
// images as they go, and what waited for what. The up's failure ends its
// stream (`failCompose`); the stream's end is the project being up
// (`endCompose`).

import { buildReducer, failBuild, initialBuild, type BuildState } from "./build";
import type { ComposeProgress, DependencyCondition, ResourceAction, ResourceKind } from "./ipc";
import { failPull, initialPull, pullReducer, type PullState } from "./pull";

export interface ResourceRow {
  kind: ResourceKind;
  name: string;
  action: ResourceAction;
}

export interface ComposeState {
  phase: "running" | "done" | "error";
  /** In the order first named, each with its latest action. */
  resources: ResourceRow[];
  /** Services' images being built, by service. */
  builds: { service: string; build: BuildState }[];
  /** Services' images being pulled, by service. */
  pulls: { service: string; image: string; pull: PullState }[];
  /** What waited for what, and warnings, in order. */
  notes: { kind: "waiting" | "warning"; text: string }[];
  error?: string;
}

export function initialCompose(): ComposeState {
  return { phase: "running", resources: [], builds: [], pulls: [], notes: [] };
}

const CONDITION: Record<DependencyCondition, string> = {
  started: "start",
  healthy: "be healthy",
  completed_successfully: "complete successfully",
};

/** `list` with the entry `match` finds replaced by `f` of it, or `f()`
 * of nothing added at its end. */
function upsert<T>(list: T[], match: (t: T) => boolean, f: (t?: T) => T): T[] {
  const i = list.findIndex(match);
  return i < 0 ? [...list, f()] : list.map((t, j) => (j === i ? f(t) : t));
}

export function composeReducer(s: ComposeState, m: ComposeProgress): ComposeState {
  switch (m.type) {
    case "resource":
      return {
        ...s,
        resources: upsert(
          s.resources,
          (r) => r.kind === m.kind && r.name === m.name,
          () => ({ kind: m.kind, name: m.name, action: m.action }),
        ),
      };
    case "build":
      return {
        ...s,
        builds: upsert(
          s.builds,
          (b) => b.service === m.service,
          (b) => ({ service: m.service, build: buildReducer(b?.build ?? initialBuild(), m.event) }),
        ),
      };
    case "pull":
      return {
        ...s,
        pulls: upsert(
          s.pulls,
          (p) => p.service === m.service,
          (p) => ({ service: m.service, image: m.image, pull: pullReducer(p?.pull ?? initialPull(m.image), m.event) }),
        ),
      };
    case "waiting":
      return { ...s, notes: [...s.notes, { kind: "waiting", text: `${m.service} waits for ${m.on} to ${CONDITION[m.condition]}` }] };
    case "warning":
      return { ...s, notes: [...s.notes, { kind: "warning", text: m.message }] };
  }
}

/** The stream ended: the project is up. */
export function endCompose(s: ComposeState): ComposeState {
  return s.phase === "running" ? { ...s, phase: "done" } : s;
}

/** The up failed: what was being built or pulled stopped with it. */
export function failCompose(s: ComposeState, message: string): ComposeState {
  const busy = (phase: string) => phase !== "done" && phase !== "ready" && phase !== "error" && phase !== "stopped";
  return {
    ...s,
    phase: "error",
    error: message,
    builds: s.builds.map((b) => (busy(b.build.phase) ? { ...b, build: failBuild(b.build, message) } : b)),
    pulls: s.pulls.map((p) => (busy(p.pull.phase) ? { ...p, pull: failPull(p.pull, message) } : p)),
  };
}

/** Where a resource's latest action leaves it: still going, done, or (a
 * container) exited, as a one-off service does when it has done its job. */
export function actionState(a: ResourceAction): "busy" | "done" | "exited" {
  switch (a) {
    case "creating":
    case "recreating":
    case "starting":
    case "stopping":
    case "removing":
    case "building":
    case "pulling":
      return "busy";
    case "exited":
      return "exited";
    default:
      return "done";
  }
}

/** "Created", as compose prints it. */
export function actionText(a: ResourceAction): string {
  return a.charAt(0).toUpperCase() + a.slice(1);
}
