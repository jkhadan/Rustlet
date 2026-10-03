// @vitest-environment jsdom
// The isolation inspector against what the report's fields mean
// (rustlet-spec isolation.rs).

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ContainerInspect, Isolation, Namespace } from "@/bindings";

const h = vi.hoisted(() => {
  const handlers: Record<string, (args: any) => unknown> = {};
  const invoke = async (cmd: string, args?: any) => {
    const f = handlers[cmd];
    if (!f) throw { kind: "failed", message: `no handler for ${cmd}` };
    return f(args);
  };
  return { handlers, invoke };
});
vi.mock("@tauri-apps/api/core", () => ({ Channel: class {}, invoke: h.invoke }));

import { IsolationTab } from "./IsolationTab";

afterEach(cleanup);

const ns = (kind: string, over: Partial<Namespace> = {}): Namespace => ({
  kind,
  mode: "new",
  path: null,
  inode: 4026532000,
  host_inode: 4026531000,
  shared_with_host: false,
  shared_with: [],
  ...over,
});

function report(namespaces: Namespace[]): Isolation {
  return {
    id: "c1",
    name: "api",
    pid: 4242,
    namespaces,
    uid_map: [],
    gid_map: [],
    credentials: { uid: 0, gid: 0, additional_gids: [], host_uid: 0, host_gid: 0 },
    capabilities: { effective: [], permitted: [], inheritable: [], bounding: [], ambient: [], known: [] },
    seccomp: { mode: "filter", filters: 1, no_new_privs: true, profile: null },
    filesystem: { rootfs: "/x/rootfs", read_only: false, masked_paths: [], readonly_paths: [], mounts: [] },
    devices: [],
    cgroup: {
      path: "/rustlet/c1",
      memory_current: 0,
      memory_max: null,
      swap_current: null,
      swap_max: null,
      pids_current: 1,
      pids_max: null,
      cpu_quota: null,
      cpu_period: 100000,
      cpu_weight: null,
      cpu_usage_usec: 0,
      oom_kills: 0,
    },
    oom_score_adj: 0,
  };
}

describe("the summary", () => {
  it("doesn't count a namespace shared with another container as its own", async () => {
    // `--network container:web`: its network namespace is web's.
    h.handlers.container_isolation = () =>
      report([
        ...["mnt", "uts", "ipc", "pid", "cgroup"].map((k) => ns(k)),
        ns("net", { mode: "join", path: "/proc/4100/ns/net", shared_with: ["web"] }),
        ns("user", { mode: "host", inode: 4026531837, host_inode: 4026531837, shared_with_host: true }),
        ns("time", { mode: "host", inode: 4026531834, host_inode: 4026531834, shared_with_host: true }),
      ]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <IsolationTab container={{ id: "c1" } as ContainerInspect} running />
      </QueryClientProvider>,
    );
    await screen.findByTestId("isolation");
    expect(screen.getByText(/namespaces its own/).textContent).toBe("5 of 8 namespaces its own, 1 shared with other containers");
  });
});
