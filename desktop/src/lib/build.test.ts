import { describe, expect, it } from "vitest";

import type { BuildEvent } from "@/bindings";

import {
  buildOptions,
  buildReducer,
  displayLine,
  emptyBuildForm,
  endBuild,
  failBuild,
  initialBuild,
  MAX_STEP_LINES,
  parseBuildArgs,
  parseTags,
  stopBuild,
} from "./build";

const fold = (events: BuildEvent[], s = initialBuild()) => events.reduce(buildReducer, s);

/** The start of the milestone's build: python:3-slim, pip, the app. */
const start: BuildEvent[] = [
  { type: "context", files: 3, bytes: 1200 },
  { type: "stage", index: 0, name: null, base: "python:3-slim" },
  { type: "step", step: 1, total: 4, instruction: "FROM python:3-slim" },
  { type: "pull", event: { status: "resolving", reference: "python:3-slim" } },
  { type: "pull", event: { status: "ready", reference: "python:3-slim", manifest: "sha256:m" } },
  { type: "step_done", step: 1, layer: null },
  { type: "step", step: 2, total: 4, instruction: "RUN pip install redis" },
  { type: "container", step: 2, id: "c0ffee" },
];

describe("build progress", () => {
  it("follows a build from its context to its image", () => {
    let s = fold(start);
    expect(s.phase).toBe("building");
    expect(s.context).toEqual({ files: 3, bytes: 1200 });
    expect(s.steps.map((st) => [st.step, st.state, st.stage])).toEqual([
      [1, "done", 0],
      [2, "running", 0],
    ]);
    expect(s.steps[0].pull?.phase).toBe("ready");
    expect(s.steps[1].container).toBe("c0ffee");
    s = fold(
      [
        { type: "output", step: 2, stream: "stdout", text: "Collecting redis\nInstalling" },
        { type: "output", step: 2, stream: "stdout", text: " collected packages\n" },
        { type: "step_done", step: 2, layer: "sha256:l2" },
        { type: "step", step: 3, total: 4, instruction: "COPY app.py ." },
        { type: "cached", step: 3 },
        { type: "step_done", step: 3, layer: "sha256:l3" },
        { type: "step", step: 4, total: 4, instruction: 'CMD ["python", "app.py"]' },
        { type: "step_done", step: 4, layer: null },
        { type: "done", id: "sha256:img", names: ["docker.io/library/hits:latest"] },
      ],
      s,
    );
    expect(s.phase).toBe("done");
    expect(s.image).toEqual({ id: "sha256:img", names: ["docker.io/library/hits:latest"] });
    expect(s.steps.map((st) => st.state)).toEqual(["done", "done", "cached", "done"]);
    expect(s.steps[1]).toMatchObject({ layer: "sha256:l2", container: undefined });
    expect(s.steps[1].output).toEqual([
      { stream: "stdout", text: "Collecting redis" },
      { stream: "stdout", text: "Installing collected packages" },
    ]);
    expect(s.steps[2].layer).toBe("sha256:l3");
  });

  it("is sending its context until the daemon has it", () => {
    expect(initialBuild().phase).toBe("sending");
    expect(fold([{ type: "warning", message: "one or more build args were not consumed: V" }])).toMatchObject({
      phase: "sending",
      warnings: ["one or more build args were not consumed: V"],
    });
  });

  it("keeps steps apart across stages, each step in its own stage", () => {
    const s = fold([
      { type: "stage", index: 0, name: "builder", base: "golang:1.25" },
      { type: "step", step: 1, total: 3, instruction: "FROM golang:1.25 AS builder" },
      { type: "stage", index: 2, name: null, base: "alpine" },
      { type: "step", step: 2, total: 3, instruction: "FROM alpine" },
      { type: "step", step: 3, total: 3, instruction: "COPY --from=builder /app /app" },
    ]);
    expect(s.stages.map((st) => st.index)).toEqual([0, 2]);
    expect(s.steps.map((st) => st.stage)).toEqual([0, 2, 2]);
    // A step starts when the one before is done.
    expect(s.steps.map((st) => st.state)).toEqual(["done", "done", "running"]);
  });

  it("joins output into lines, keeping stdout and stderr apart", () => {
    const s = fold([
      ...start,
      { type: "output", step: 2, stream: "stdout", text: "a" },
      { type: "output", step: 2, stream: "stderr", text: "warning: x\n" },
      { type: "output", step: 2, stream: "stdout", text: "b\nc" },
    ]);
    const step = s.steps[1];
    expect(step.output).toEqual([
      { stream: "stdout", text: "a" },
      { stream: "stderr", text: "warning: x" },
      { stream: "stdout", text: "b" },
    ]);
    expect(step.partial).toEqual({ stream: "stdout", text: "c" });
  });

  it("keeps a step's last lines, counting what it dropped", () => {
    const many = Array.from({ length: MAX_STEP_LINES + 5 }, (_, i) => `line ${i}`).join("\n") + "\n";
    const s = fold([...start, { type: "output", step: 2, stream: "stdout", text: many }]);
    expect(s.steps[1].output).toHaveLength(MAX_STEP_LINES);
    expect(s.steps[1].dropped).toBe(5);
    expect(s.steps[1].output[0].text).toBe("line 5");
  });

  it("a failure marks the step under way as the one that failed", () => {
    const s = failBuild(fold(start), "The command '/bin/sh -c pip install redis' returned a non-zero code: 1");
    expect(s.phase).toBe("error");
    expect(s.error).toMatch(/non-zero code: 1/);
    expect(s.steps.map((st) => st.state)).toEqual(["done", "failed"]);
    // The daemon's own `error` event, should one arrive as an item.
    expect(fold([...start, { type: "error", message: "x" }]).steps[1].state).toBe("failed");
  });

  it("a failure while pulling the base image stops the pull too", () => {
    const s = failBuild(
      fold([
        { type: "stage", index: 0, name: null, base: "nope:1" },
        { type: "step", step: 1, total: 2, instruction: "FROM nope:1" },
        { type: "pull", event: { status: "resolving", reference: "nope:1" } },
      ]),
      "nope:1: manifest unknown",
    );
    expect(s.steps[0].pull).toMatchObject({ phase: "error", error: "nope:1: manifest unknown" });
  });

  it("stopped from here, it says so; a finished build stays as it ended", () => {
    const s = stopBuild(fold(start));
    expect(s.phase).toBe("stopped");
    expect(s.steps.map((st) => st.state)).toEqual(["done", "stopped"]);
    const done = fold([...start, { type: "done", id: "sha256:x", names: [] }]);
    expect(stopBuild(done)).toBe(done);
    expect(endBuild(done)).toBe(done);
  });

  it("a stream that ends without a result was cut short", () => {
    expect(endBuild(fold(start))).toMatchObject({ phase: "error", error: "rustletd ended the build without a result" });
  });

  it("shows a line redrawn with carriage returns as it was left", () => {
    expect(displayLine("10%\r50%\r100%")).toBe("100%");
    expect(displayLine("done\r")).toBe("done");
    expect(displayLine("plain")).toBe("plain");
  });
});

describe("the build form", () => {
  it("takes tags separated any way, each once", () => {
    expect(parseTags(" hits:latest, hits:1\nregistry.example/hits:1  hits:1 ")).toEqual([
      "hits:latest",
      "hits:1",
      "registry.example/hits:1",
    ]);
    expect(parseTags("")).toEqual([]);
  });

  it("takes build args a KEY=VALUE line each, values as typed", () => {
    expect(parseBuildArgs("V=1\n\n# a comment\nGREETING=hello world\r\nEMPTY=\nURL=http://x/?a=b")).toEqual({
      V: "1",
      GREETING: "hello world",
      EMPTY: "",
      URL: "http://x/?a=b",
    });
    expect(() => parseBuildArgs("HTTP_PROXY")).toThrow('build arg "HTTP_PROXY": give KEY=VALUE');
    expect(() => parseBuildArgs("=x")).toThrow(/give KEY=VALUE/);
  });

  it("becomes the API's options, the rest left to its defaults", () => {
    const o = buildOptions({ ...emptyBuildForm, tags: "hits", buildArgs: "V=1", target: " ", noCache: true, pull: true });
    expect(o).toEqual({ tags: ["hits"], build_args: { V: "1" }, target: null, no_cache: true, pull: "always", network: "bridge" });
    expect(buildOptions({ ...emptyBuildForm, target: "builder", network: "host" })).toMatchObject({
      target: "builder",
      pull: "missing",
      network: "host",
    });
  });
});
