// A build's progress, folded from its events (`BuildEvent`, in the order
// rustletd sends them: `context` once it has the context; per stage built
// `stage`, then per instruction `step`, then `cached` or the work (`pull`
// events for a base image, `container` and `output` for a RUN), then
// `step_done`; last `done`). A failure ends the stream: rustlet-client makes
// the daemon's `error` event the stream's error, which arrives here as
// `failBuild`. And the form that starts one.

import type { BuildEvent, BuildOptions, LogStream } from "@/bindings";

import { failPull, initialPull, pullReducer, type PullState } from "./pull";

/** Lines of output a step keeps; earlier ones are dropped, and counted. */
export const MAX_STEP_LINES = 2000;
/** Character limits include output without any newline. */
export const MAX_STEP_LINE_CHARS = 16 * 1024;
export const MAX_STEP_OUTPUT_CHARS = 2 * 1024 * 1024;

/** `stopped`: the build was stopped, or failed, while it ran. */
export type StepState = "running" | "cached" | "done" | "failed" | "stopped";

export interface OutputLine {
  stream: LogStream;
  text: string;
}

export interface BuildStep {
  /** From 1, over every stage built (`FROM` lines included). */
  step: number;
  total: number;
  /** As written, its variables expanded. */
  instruction: string;
  /** The stage it is in (its index in the file). */
  stage: number | null;
  state: StepState;
  /** The layer it added (`RUN`, `COPY`, `ADD`), once done. */
  layer?: string | null;
  /** A `RUN` step's container, while it runs. */
  container?: string;
  /** What a `RUN` printed, line by line. */
  output: OutputLine[];
  /** The last line, while its newline hasn't come. */
  partial?: OutputLine;
  /** Lines dropped from the start of `output`. */
  dropped: number;
  /** Characters discarded from oversized lines (separate from dropped lines). */
  droppedChars: number;
  /** A `FROM` step's pull of its base image. */
  pull?: PullState;
}

export interface BuildStage {
  index: number;
  name: string | null;
  base: string;
}

/** `sending`: the daemon is still receiving the context. */
export type BuildPhase = "sending" | "building" | "done" | "error" | "stopped";

export interface BuildState {
  phase: BuildPhase;
  /** What the daemon got: entries, and bytes of file data. */
  context?: { files: number; bytes: number };
  stages: BuildStage[];
  steps: BuildStep[];
  warnings: string[];
  error?: string;
  /** The image built: its id (manifest digest) and names. */
  image?: { id: string; names: string[] };
}

export function initialBuild(): BuildState {
  return { phase: "sending", stages: [], steps: [], warnings: [] };
}

/** `s` with step `step` changed by `f` (steps are numbered over the whole
 * build, so the number is enough). */
function updateStep(s: BuildState, step: number, f: (st: BuildStep) => BuildStep): BuildState {
  const i = s.steps.findLastIndex((x) => x.step === step);
  if (i < 0) return s;
  const steps = s.steps.slice();
  steps[i] = f(steps[i]);
  return { ...s, steps };
}

/** Steps still running, as `state` says they ended. */
function settle(steps: BuildStep[], state: StepState): BuildStep[] {
  return steps.map((st) => (st.state === "running" ? { ...st, state } : st));
}

/** `text` added to a step's output. Output comes in pieces, not lines: a
 * piece continues the line in progress (of the same stream; another
 * stream's piece ends it), and its own last line waits for its newline. */
function appendOutput(st: BuildStep, stream: LogStream, text: string): BuildStep {
  const pieces = text.split("\n");
  const lines: OutputLine[] = [];
  let partial = st.partial;
  let droppedChars = st.droppedChars;
  pieces.forEach((piece, i) => {
    if (partial && partial.stream !== stream) {
      lines.push(partial);
      partial = undefined;
    }
    let joined = (partial?.text ?? "") + piece;
    if (joined.length > MAX_STEP_LINE_CHARS) {
      const start = joined.length - MAX_STEP_LINE_CHARS;
      // Keep the tail, without starting in the middle of a UTF-16 pair.
      const low = joined.charCodeAt(start);
      const cut = start + (low >= 0xdc00 && low <= 0xdfff ? 1 : 0);
      droppedChars += cut;
      joined = joined.slice(cut);
    }
    partial = undefined;
    if (i < pieces.length - 1) lines.push({ stream, text: joined });
    else if (joined) partial = { stream, text: joined };
  });
  let output = lines.length ? st.output.concat(lines) : st.output;
  let dropped = st.dropped;
  if (output.length > MAX_STEP_LINES) {
    dropped += output.length - MAX_STEP_LINES;
    output = output.slice(output.length - MAX_STEP_LINES);
  }
  let chars = output.reduce((sum, line) => sum + line.text.length, partial?.text.length ?? 0);
  let remove = 0;
  while (chars > MAX_STEP_OUTPUT_CHARS && remove < output.length) {
    chars -= output[remove++].text.length;
  }
  if (remove) {
    dropped += remove;
    output = output.slice(remove);
  }
  return { ...st, output, partial, dropped, droppedChars };
}

export function buildReducer(s: BuildState, e: BuildEvent): BuildState {
  switch (e.type) {
    case "context":
      return { ...s, phase: "building", context: { files: e.files, bytes: e.bytes } };
    case "stage":
      return { ...s, phase: "building", stages: [...s.stages, { index: e.index, name: e.name, base: e.base }] };
    case "step": {
      const step: BuildStep = {
        step: e.step,
        total: e.total,
        instruction: e.instruction,
        stage: s.stages.at(-1)?.index ?? null,
        state: "running",
        output: [],
        dropped: 0,
        droppedChars: 0,
      };
      // A step starts when the one before is done, whatever said so.
      return { ...s, phase: "building", steps: [...settle(s.steps, "done"), step] };
    }
    case "pull": {
      // The base image of the step under way, a FROM.
      const last = s.steps.at(-1);
      if (!last) return s;
      const base = s.stages.at(-1)?.base ?? "";
      return updateStep(s, last.step, (st) => ({ ...st, pull: pullReducer(st.pull ?? initialPull(base), e.event) }));
    }
    case "cached":
      return updateStep(s, e.step, (st) => ({ ...st, state: "cached" }));
    case "container":
      return updateStep(s, e.step, (st) => ({ ...st, container: e.id }));
    case "output":
      return updateStep(s, e.step, (st) => appendOutput(st, e.stream, e.text));
    case "step_done":
      return updateStep(s, e.step, (st) => ({
        ...st,
        state: st.state === "cached" ? "cached" : "done",
        layer: e.layer,
        container: undefined,
      }));
    case "warning":
      return { ...s, warnings: [...s.warnings, e.message] };
    case "done":
      return { ...s, phase: "done", steps: settle(s.steps, "done"), image: { id: e.id, names: e.names } };
    case "error":
      return failBuild(s, e.message);
  }
}

/** The build failed (its stream's error: the daemon's `error` event, a
 * broken connection, a context that couldn't be packed): the step under
 * way is the one that failed. */
export function failBuild(s: BuildState, message: string): BuildState {
  return {
    ...s,
    phase: "error",
    error: message,
    steps: s.steps.map((st) =>
      st.state === "running" ? { ...st, state: "failed", pull: st.pull && failPull(st.pull, message) } : st,
    ),
  };
}

/** The build was stopped from here (its stream cancelled: the daemon stops
 * at its next event). */
export function stopBuild(s: BuildState): BuildState {
  if (s.phase === "done" || s.phase === "error") return s;
  return { ...s, phase: "stopped", steps: settle(s.steps, "stopped") };
}

/** The stream ended. A build that ended without `done` was cut short. */
export function endBuild(s: BuildState): BuildState {
  if (s.phase === "done" || s.phase === "error" || s.phase === "stopped") return s;
  return failBuild(s, "rustletd ended the build without a result");
}

/** A line of output as a terminal would leave it: what follows its last
 * carriage return (a progress bar redrawn in place shows its last state). */
export function displayLine(text: string): string {
  const t = text.endsWith("\r") ? text.slice(0, -1) : text;
  return t.slice(t.lastIndexOf("\r") + 1);
}

/** The Build view's form. */
export interface BuildForm {
  context: string;
  containerfile: string;
  /** Names, separated by commas, spaces or lines. */
  tags: string;
  /** `KEY=VALUE`, a line each. */
  buildArgs: string;
  target: string;
  network: string;
  noCache: boolean;
  /** Always ask the registry for the base images (`--pull`). */
  pull: boolean;
}

export const emptyBuildForm: BuildForm = {
  context: "",
  containerfile: "",
  tags: "",
  buildArgs: "",
  target: "",
  network: "bridge",
  noCache: false,
  pull: false,
};

/** The image's names, as `-t` takes them, each once. */
export function parseTags(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).filter(Boolean))];
}

/** `--build-arg` values, a `KEY=VALUE` line each (the value as typed,
 * spaces and all; empty lines and `#` comments skipped). A bare `KEY`, which
 * the CLI fills from its shell's environment, has no environment to come
 * from here, and is refused. */
export function parseBuildArgs(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    if (!line.trim() || line.trim().startsWith("#")) continue;
    const eq = line.indexOf("=");
    const key = (eq < 0 ? line : line.slice(0, eq)).trim();
    if (eq < 0 || !key) throw new Error(`build arg "${line.trim()}": give KEY=VALUE`);
    out[key] = line.slice(eq + 1);
  }
  return out;
}

/** The form as the API's `BuildOptions` (the app sets `dockerfile`). */
export function buildOptions(f: BuildForm): Partial<BuildOptions> {
  return {
    tags: parseTags(f.tags),
    build_args: parseBuildArgs(f.buildArgs),
    target: f.target.trim() || null,
    no_cache: f.noCache,
    pull: f.pull ? "always" : "missing",
    network: f.network || "bridge",
  };
}
