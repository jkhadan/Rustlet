// @vitest-environment jsdom
// The overview against what the daemon means by the container's config.

import { cleanup, render } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it } from "vitest";

import type { ContainerInspect } from "@/bindings";
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
