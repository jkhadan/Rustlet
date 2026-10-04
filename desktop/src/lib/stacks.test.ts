import { describe, expect, it } from "vitest";

import type { ContainerStatus, Health } from "@/bindings";

import type { Stack, StackContainer } from "./ipc";
import { runningText, servicesOf, sortStacks, stackSummary, upAgainFiles } from "./stacks";

function container(service: string, number: number, status: ContainerStatus, health: Health["status"] | null = null): StackContainer {
  return {
    service,
    number,
    container: {
      id: `${service}${number}`.padEnd(64, "0"),
      name: `hits-${service}-${number}`,
      image: service,
      image_id: "sha256:x",
      command: [],
      created: "2026-10-03T00:00:00Z",
      state: {
        status,
        pid: null,
        exit_code: null,
        oom_killed: false,
        error: null,
        started_at: null,
        finished_at: null,
        restart_count: 0,
        health: health && { status: health, failing_streak: 0, log: [] },
      },
      labels: {},
      ports: [],
      network_mode: "hits_default",
    },
  };
}

const stack = (name: string, containers: StackContainer[], config_files: string[] = []): Stack => ({
  name,
  working_dir: null,
  config_files,
  containers,
});

describe("a stack", () => {
  it("groups its containers by service, in the daemon's order", () => {
    const s = stack("hits", [container("redis", 1, "running"), container("web", 1, "running"), container("web", 2, "exited")]);
    expect(servicesOf(s).map((g) => [g.service, g.containers.map((c) => c.number)])).toEqual([
      ["redis", [1]],
      ["web", [1, 2]],
    ]);
  });

  it("counts what runs, as compose ls does", () => {
    const all = stackSummary(stack("hits", [container("redis", 1, "running"), container("web", 1, "paused")]));
    expect(all).toMatchObject({ running: 2, total: 2, state: "running" });
    expect(runningText(all)).toBe("running 2/2");
    const some = stackSummary(stack("hits", [container("redis", 1, "running"), container("web", 1, "exited")]));
    expect(some).toMatchObject({ running: 1, total: 2, state: "partial" });
    const none = stackSummary(stack("hits", [container("web", 1, "exited"), container("web", 2, "created")]));
    expect(none).toMatchObject({ running: 0, state: "stopped" });
    expect(stackSummary(stack("empty", [])).state).toBe("stopped");
  });

  it("counts the health of what runs, not of what ran", () => {
    const s = stackSummary(
      stack("hits", [
        container("redis", 1, "running", "starting"),
        container("web", 1, "running", "unhealthy"),
        container("web", 2, "running", "healthy"),
        // The verdict of a run that ended is not the stack's now.
        container("web", 3, "exited", "unhealthy"),
      ]),
    );
    expect(s).toMatchObject({ unhealthy: 1, starting: 1, running: 3, total: 4 });
  });

  it("comes up again from the files its labels name, if they name any", () => {
    expect(upAgainFiles(stack("hits", [], ["/srv/hits/compose.yaml", "/srv/hits/compose.override.yaml"]))).toEqual([
      "/srv/hits/compose.yaml",
      "/srv/hits/compose.override.yaml",
    ]);
    expect(upAgainFiles(stack("x", [], []))).toBeNull();
    expect(upAgainFiles(stack("x", [], [""]))).toBeNull();
  });

  it("stacks are listed by name", () => {
    expect(sortStacks([stack("web", []), stack("api", []), stack("db", [])]).map((s) => s.name)).toEqual(["api", "db", "web"]);
  });
});
