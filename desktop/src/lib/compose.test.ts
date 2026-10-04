import { describe, expect, it } from "vitest";

import { actionState, actionText, composeReducer, endCompose, failCompose, initialCompose } from "./compose";
import type { ComposeProgress } from "./ipc";

const fold = (messages: ComposeProgress[]) => messages.reduce(composeReducer, initialCompose());

/** The milestone's up: a network, redis pulled and healthy, web built. */
const up: ComposeProgress[] = [
  { type: "resource", kind: "network", name: "hits_default", action: "creating" },
  { type: "resource", kind: "network", name: "hits_default", action: "created" },
  { type: "pull", service: "redis", image: "redis:7-alpine", event: { status: "resolving", reference: "redis:7-alpine" } },
  { type: "build", service: "web", event: { type: "context", files: 3, bytes: 1200 } },
  { type: "build", service: "web", event: { type: "step", step: 1, total: 4, instruction: "FROM python:3-slim" } },
  { type: "pull", service: "redis", image: "redis:7-alpine", event: { status: "ready", reference: "redis:7-alpine", manifest: "sha256:r" } },
  { type: "resource", kind: "container", name: "hits-redis-1", action: "creating" },
  { type: "resource", kind: "container", name: "hits-redis-1", action: "started" },
  { type: "waiting", service: "web", on: "redis", condition: "healthy" },
  { type: "resource", kind: "container", name: "hits-redis-1", action: "healthy" },
];

describe("compose up progress", () => {
  it("keeps each resource's latest action, in the order first named", () => {
    const s = fold(up);
    expect(s.resources).toEqual([
      { kind: "network", name: "hits_default", action: "created" },
      { kind: "container", name: "hits-redis-1", action: "healthy" },
    ]);
    expect(s.phase).toBe("running");
  });

  it("follows each service's build and pull", () => {
    const s = fold(up);
    expect(s.builds.map((b) => [b.service, b.build.phase, b.build.steps.length])).toEqual([["web", "building", 1]]);
    expect(s.pulls.map((p) => [p.service, p.image, p.pull.phase])).toEqual([["redis", "redis:7-alpine", "ready"]]);
  });

  it("says what waited for what, and the warnings, in order", () => {
    const s = fold([...up, { type: "warning", message: "service web: ports 8000 published twice" }]);
    expect(s.notes).toEqual([
      { kind: "waiting", text: "web waits for redis to be healthy" },
      { kind: "warning", text: "service web: ports 8000 published twice" },
    ]);
    const done = fold([{ type: "waiting", service: "app", on: "migrate", condition: "completed_successfully" }]);
    expect(done.notes[0].text).toBe("app waits for migrate to complete successfully");
  });

  it("is done when its stream ends", () => {
    expect(endCompose(fold(up)).phase).toBe("done");
  });

  it("a failure stops what was being built or pulled, and stays the last word", () => {
    const pulling = fold([
      { type: "pull", service: "db", image: "postgres:17", event: { status: "resolving", reference: "postgres:17" } },
      ...up,
    ]);
    const s = failCompose(pulling, "redis is unhealthy");
    expect(s).toMatchObject({ phase: "error", error: "redis is unhealthy" });
    expect(s.builds[0].build.phase).toBe("error");
    expect(s.pulls.map((p) => p.pull.phase)).toEqual(["error", "ready"]);
    expect(endCompose(s)).toBe(s);
  });

  it("reads each action as busy, done or exited, in compose's words", () => {
    expect(actionState("creating")).toBe("busy");
    expect(actionState("pulling")).toBe("busy");
    expect(actionState("healthy")).toBe("done");
    expect(actionState("removed")).toBe("done");
    expect(actionState("exited")).toBe("exited");
    expect(actionText("recreated")).toBe("Recreated");
  });
});
