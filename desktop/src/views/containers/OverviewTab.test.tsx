// @vitest-environment jsdom
// The overview against what the daemon means by the container's config.

import { cleanup, render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it } from "vitest";

import type { ContainerInspect, Health } from "@/bindings";
import { TooltipProvider } from "@/components/ui/tooltip";

import { OverviewTab } from "./OverviewTab";

afterEach(cleanup);

function inspect(over: { config?: Record<string, unknown>; mounts?: unknown[] } = {}): ContainerInspect {
  return {
    id: "a".repeat(64),
    name: "db",
    created: "2026-10-03T00:00:00Z",
    image: "postgres",
    image_id: "sha256:" + "b".repeat(64),
    command: ["postgres"],
    config: {
      image: "postgres",
      name: "db",
      cmd: [],
      entrypoint: null,
      env: [],
      user: null,
      workdir: null,
      hostname: null,
      tty: false,
      open_stdin: false,
      stdin_once: false,
      labels: {},
      read_only: false,
      userns: "host",
      memory: null,
      cpus: null,
      pids_limit: null,
      restart: { name: "no", max_retries: 0 },
      auto_remove: false,
      stop_signal: null,
      stop_timeout: null,
      cap_add: [],
      cap_drop: [],
      privileged: false,
      security_opt: [],
      devices: [],
      network: "bridge",
      network_aliases: [],
      ip: null,
      ip6: null,
      extra_networks: [],
      ports: [],
      publish_all: false,
      dns: [],
      dns_search: [],
      dns_options: [],
      extra_hosts: [],
      mounts: [],
      ...over.config,
    },
    state: { status: "running", pid: 42, exit_code: null, oom_killed: false, error: null, started_at: "2026-10-03T00:00:01Z", finished_at: null, restart_count: 0 },
    hostname: "aaaaaaaaaaaa",
    rootfs: null,
    dir: "/x",
    log_path: "/x/container.log",
    cgroup: "/rustlet/a",
    uid_map: null,
    network: { mode: "bridge", networks: [], ports: [], dns_names: [] },
    mounts: over.mounts ?? [],
  } as unknown as ContainerInspect;
}

function show(c: ContainerInspect) {
  render(
    <MemoryRouter>
      <TooltipProvider>
        <OverviewTab container={c} />
      </TooltipProvider>
    </MemoryRouter>,
  );
}

const security = () => [...document.querySelectorAll("dt")].find((d) => d.textContent === "Security")!.nextElementSibling!.textContent;

describe("overview", () => {
  it("a named volume with a long name is not called anonymous", () => {
    const name = "my-application-postgres-data"; // valid_volume_name, 28 characters
    show(inspect({ mounts: [{ type: "volume", name, source: `/var/lib/rustlet/volumes/${name}/_data`, destination: "/var/lib/postgresql/data", read_only: false }] }));
    expect(document.body.textContent).not.toContain("(anonymous)");
    expect(document.body.textContent).toContain(name);
  });

  it("seccomp turned off with the colon syntax the daemon accepts is not 'defaults'", () => {
    // rustletd spec.rs check(): opt.split_once(['=', ':']), so seccomp:unconfined
    // runs the container without a profile.
    show(inspect({ config: { security_opt: ["seccomp:unconfined"] } }));
    expect(security()).toBe("seccomp unconfined");
  });

  it("no-new-privileges turned off (Rustlets defaults it on) is not 'defaults'; the last setting wins", () => {
    show(inspect({ config: { security_opt: ["no-new-privileges=false"] } }));
    expect(security()).toBe("no-new-privileges off");
    cleanup();
    show(inspect({ config: { security_opt: ["no-new-privileges=false", "no-new-privileges"] } }));
    expect(security()).toBe("defaults");
  });
});

describe("health", () => {
  const check = (second: number, exit_code: number, output: string) => ({
    start: `2026-10-03T00:01:${String(second).padStart(2, "0")}.000000000Z`,
    end: `2026-10-03T00:01:${String(second).padStart(2, "0")}.020000000Z`,
    exit_code,
    output,
  });

  function withHealth(health: Health | null, healthcheck: unknown = null, status = "running") {
    const c = inspect({ config: { healthcheck } });
    c.state = { ...c.state, status: status as ContainerInspect["state"]["status"], health };
    return c;
  }

  it("shows the verdict, the streak, the check and its last results, newest first", () => {
    const health: Health = {
      status: "unhealthy",
      failing_streak: 3,
      log: [check(0, 0, "PONG\n"), check(10, 1, "Could not connect to Redis\n"), check(20, -1, "")],
    };
    show(withHealth(health, { test: ["CMD-SHELL", "redis-cli ping"], interval: 10e9, timeout: null, start_period: null, start_interval: null, retries: 3 }));
    const card = screen.getByTestId("health");
    expect(within(card).getByText("unhealthy")).toBeTruthy();
    expect(within(card).getByText("3 checks failed in a row")).toBeTruthy();
    expect(within(card).getByText("redis-cli ping")).toBeTruthy();
    expect(within(card).getByText("every 10s · 3 retries")).toBeTruthy();
    const rows = [...within(card).getByTestId("health-checks").querySelectorAll("tbody tr")] as HTMLElement[];
    expect(rows.map((r) => r.dataset.outcome)).toEqual(["error", "failed", "passed"]);
    expect(rows[0].textContent).toContain("timed out or couldn't run");
    expect(rows[1].textContent).toContain("Could not connect to Redis");
    expect(rows[2].textContent).toContain("20 ms");
  });

  it("of a container whose image has the check, says so; none without one", () => {
    show(withHealth({ status: "starting", failing_streak: 0, log: [] }));
    expect(within(screen.getByTestId("health")).getByText("the image's HEALTHCHECK")).toBeTruthy();
    expect(screen.getByText("No check has run yet.")).toBeTruthy();
    cleanup();
    show(withHealth(null));
    expect(screen.queryByTestId("health")).toBeNull();
    cleanup();
    show(withHealth(null, { test: ["NONE"], interval: null, timeout: null, start_period: null, start_interval: null, retries: null }));
    expect(screen.queryByTestId("health")).toBeNull();
  });

  it("of a stopped container is what its last run's checks left", () => {
    show(withHealth({ status: "healthy", failing_streak: 0, log: [check(0, 0, "")] }, null, "exited"));
    expect(screen.getByText("as the checks of its last run left it")).toBeTruthy();
  });
});
