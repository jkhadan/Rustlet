import { describe, expect, it } from "vitest";

import type { ContainerStatus, Health, HealthConfig } from "@/bindings";

import {
  checkMillis,
  checkOutcome,
  checksNewestFirst,
  describeTest,
  healthPollMs,
  healthSettings,
  shownHealth,
} from "./health";

const health = (status: Health["status"]): Health => ({ status, failing_streak: 0, log: [] });

const config = (over: Partial<HealthConfig>): HealthConfig => ({
  test: [],
  interval: null,
  timeout: null,
  start_period: null,
  start_interval: null,
  retries: null,
  ...over,
});

describe("health beside a status", () => {
  it("shows the verdict while the container runs or is paused", () => {
    expect(shownHealth({ status: "running", health: health("healthy") })).toBe("healthy");
    expect(shownHealth({ status: "paused", health: health("unhealthy") })).toBe("unhealthy");
    expect(shownHealth({ status: "running", health: health("starting") })).toBe("starting");
  });

  it("shows nothing without a healthcheck, or for a run that has ended", () => {
    expect(shownHealth({ status: "running", health: null })).toBeNull();
    // The daemon keeps the last verdict after the run: it's about that run.
    for (const status of ["exited", "created", "restarting", "dead"] as ContainerStatus[]) {
      expect(shownHealth({ status, health: health("unhealthy") })).toBeNull();
    }
  });
});

describe("checks", () => {
  const check = (start: string, end: string, exit_code: number) => ({ start, end, exit_code, output: "" });

  it("come newest first, with how long each took and what its code means", () => {
    const h: Health = {
      status: "unhealthy",
      failing_streak: 2,
      log: [
        check("2026-10-03T10:00:00.000000000Z", "2026-10-03T10:00:00.025000000Z", 0),
        check("2026-10-03T10:00:30.000000000Z", "2026-10-03T10:00:31.500000000Z", 1),
        check("2026-10-03T10:01:00.000000000Z", "2026-10-03T10:01:30.000000000Z", -1),
      ],
    };
    const checks = checksNewestFirst(h);
    expect(checks.map((c) => c.exit_code)).toEqual([-1, 1, 0]);
    expect(h.log[0].exit_code).toBe(0); // the daemon's order, left alone
    expect(checks.map(checkMillis)).toEqual([30_000, 1_500, 25]);
    expect(checks.map(checkOutcome)).toEqual(["error", "failed", "passed"]);
    expect(checkMillis(check("", "x", 0))).toBeNull();
  });
});

describe("a container's healthcheck", () => {
  it("names its test as it runs", () => {
    expect(describeTest(null)).toEqual({ kind: "image", command: "" });
    expect(describeTest(config({ interval: 5e9 }))).toEqual({ kind: "image", command: "" });
    expect(describeTest(config({ test: ["NONE"] }))).toEqual({ kind: "none", command: "" });
    expect(describeTest(config({ test: ["CMD-SHELL", "redis-cli ping | grep PONG"] }))).toEqual({
      kind: "shell",
      command: "redis-cli ping | grep PONG",
    });
    expect(describeTest(config({ test: ["CMD", "curl", "-f", "http://localhost:8000/"] }))).toEqual({
      kind: "exec",
      command: "curl -f http://localhost:8000/",
    });
  });

  it("says only the settings it was given", () => {
    expect(healthSettings(null)).toBeNull();
    expect(healthSettings(config({ test: ["CMD", "true"] }))).toBeNull();
    expect(healthSettings(config({ interval: 5e9, timeout: 3e9, retries: 1, start_period: 1.5e10 }))).toBe(
      "every 5s · timeout 3s · 1 retry · start period 15s",
    );
    expect(healthSettings(config({ retries: 0, start_interval: 5e8 }))).toBe("every 500ms while starting");
  });
});

describe("asking again while a container is checked", () => {
  const container = (status: ContainerStatus, h: Health | null, interval: number | null) =>
    ({ state: { status, health: h }, config: { healthcheck: interval == null ? null : config({ interval }) } }) as Parameters<
      typeof healthPollMs
    >[0];

  it("is about as often as it is checked, between one second and five", () => {
    expect(healthPollMs(container("running", health("healthy"), 300e6))).toBe(1_000);
    expect(healthPollMs(container("running", health("healthy"), 2e9))).toBe(2_000);
    expect(healthPollMs(container("running", health("healthy"), 30e9))).toBe(5_000);
    // The image's interval isn't in the container's config.
    expect(healthPollMs(container("running", health("starting"), null))).toBe(5_000);
    expect(healthPollMs(container("running", health("starting"), 0))).toBe(5_000);
  });

  it("is never for a container that isn't being checked", () => {
    expect(healthPollMs(undefined)).toBe(false);
    expect(healthPollMs(container("running", null, 2e9))).toBe(false);
    // Paused: its checks wait; ended: its last checks are about a run that is over.
    for (const status of ["paused", "exited", "created", "restarting", "dead"] as ContainerStatus[]) {
      expect(healthPollMs(container(status, health("healthy"), 2e9))).toBe(false);
    }
  });
});
