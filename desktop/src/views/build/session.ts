// The build under way, kept outside any component: leaving the Build view
// doesn't stop a build (one of minutes goes on while the user looks at the
// containers its steps run in), and coming back shows it where it is. Only
// Stop ends it early (its stream is cancelled, and rustletd stops the build
// at its next event), or a reload of the page, which cancels every stream.

import type { QueryClient } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";

import {
  type BuildForm,
  buildOptions,
  buildReducer,
  type BuildState,
  emptyBuildForm,
  endBuild,
  failBuild,
  initialBuild,
  stopBuild,
} from "@/lib/build";
import { keys } from "@/lib/events";
import { api, type StreamHandle } from "@/lib/ipc";

export interface BuildSession {
  /** The form as last submitted: the view starts from it. */
  form: BuildForm;
  state: BuildState | null;
  /** `Date.now()`s. */
  startedAt?: number;
  finishedAt?: number;
}

/** The build the session follows. */
interface Current {
  handle?: StreamHandle;
  stopped: boolean;
}

let session: BuildSession = { form: emptyBuildForm, state: null };
let current: Current | null = null;
const listeners = new Set<() => void>();

function update(f: (s: BuildSession) => BuildSession) {
  session = f(session);
  for (const l of listeners) l();
}

function subscribe(l: () => void) {
  listeners.add(l);
  return () => void listeners.delete(l);
}

export function useBuildSession(): BuildSession {
  return useSyncExternalStore(subscribe, () => session);
}

export function isFinished(s: BuildState): boolean {
  return s.phase === "done" || s.phase === "error" || s.phase === "stopped";
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Builds as `form` says. A form the API can't take (a build arg without
 * `=`) throws before anything starts. `client`: the images list is told
 * of the image when it is done, since an image built without a name gets
 * no event (named ones get `tag`). */
export function startBuild(form: BuildForm, client?: QueryClient): void {
  const options = buildOptions(form);
  forget();
  const me: Current = { stopped: false };
  current = me;
  const set = (f: (s: BuildState) => BuildState) =>
    update((s) => {
      if (current !== me || !s.state) return s;
      const state = f(s.state);
      return { ...s, state, finishedAt: s.finishedAt ?? (isFinished(state) ? Date.now() : undefined) };
    });
  update(() => ({ form, state: initialBuild(), startedAt: Date.now() }));
  api.images
    .build(form.context.trim(), form.containerfile.trim() || null, options, (m) => {
      if (current !== me || me.stopped) return;
      if (m.type === "items") {
        set((s) => m.items.reduce(buildReducer, s));
        if (m.items.some((e) => e.type === "done")) void client?.invalidateQueries({ queryKey: keys.images() });
      } else if (m.type === "end") {
        set(endBuild);
      } else {
        set((s) => failBuild(s, m.error.message));
      }
    })
    .then((h) => {
      if (current !== me || me.stopped) h.cancel();
      else me.handle = h;
    })
    .catch((e: unknown) => {
      // Refused before it started: no such directory, no Containerfile,
      // options the daemon won't take, no daemon.
      if (!me.stopped) set((s) => failBuild(s, message(e)));
    });
}

/** Stops the build under way: its stream is cancelled, which rustletd
 * takes for the end of the build. */
export function stopCurrentBuild(): void {
  const me = current;
  if (!me || me.stopped) return;
  me.stopped = true;
  me.handle?.cancel();
  update((s) => (s.state ? { ...s, state: stopBuild(s.state), finishedAt: s.finishedAt ?? Date.now() } : s));
}

/** Clears the view of a build that has ended (one under way is stopped). */
export function clearBuild(): void {
  forget();
  update((s) => ({ form: s.form, state: null }));
}

/** Lets go of the build followed, stopping it if it still runs. */
function forget() {
  const me = current;
  if (!me) return;
  if (session.state && !isFinished(session.state)) stopCurrentBuild();
  current = null;
}
