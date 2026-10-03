// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ContainerSummary, Network } from "@/bindings";
import { TooltipProvider } from "@/components/ui/tooltip";

const calls: [string, unknown][] = [];

function net(id: string, name: string): Network {
  return {
    id,
    name,
    driver: "bridge",
    created: "2026-10-02T12:00:00Z",
    subnet: "10.89.0.0/24",
    gateway: "10.89.0.1",
    ipv6: false,
    subnet6: null,
    gateway6: null,
    bridge: `rlb${id}`,
    internal: false,
    dns: name !== "bridge",
    labels: {},
    containers: [],
  };
}

function ctr(id: string, name: string, network_mode: string, status: "running" | "exited" = "exited"): ContainerSummary {
  return {
    id,
    name,
    image: "alpine",
    image_id: "sha256:x",
    command: [],
    created: "",
    state: { status, pid: null, exit_code: 0, oom_killed: false, error: null, started_at: null, finished_at: null, restart_count: 0 },
    labels: {},
    ports: [],
    network_mode,
  };
}

vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {},
  invoke: vi.fn(async (cmd: string, args: unknown) => {
    calls.push([cmd, args]);
    if (cmd === "network_list") return [net("n1", "bridge"), net("n2", "backend")];
    if (cmd === "container_list") {
      // web runs, but `network disconnect` took it off bridge.
      return [ctr("c0ffee", "app", "bridge"), ctr("d00d", "api", "backend"), ctr("beef", "web", "bridge", "running")];
    }
    return null;
  }),
}));

// ReactFlow needs a laid-out DOM; the graph has tests of its own (lib/topology).
vi.mock("./TopologyGraph", () => ({ TopologyGraph: () => null }));

const { NetworksPage } = await import("./NetworksPage");

afterEach(() => {
  cleanup();
  calls.length = 0;
});

async function open(network: string) {
  await waitFor(() => expect(document.querySelector(`[data-name="${network}"]`)).not.toBeNull());
  fireEvent.click(document.querySelector(`[data-name="${network}"] td`)!);
  await screen.findByText(`Network ${network}`);
}

function page() {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <TooltipProvider>
        <MemoryRouter>
          <NetworksPage />
        </MemoryRouter>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

const choices = () => [...document.querySelectorAll("option")].map((o) => o.value).filter(Boolean);

describe("connecting a container from a network's details", () => {
  it("sends what the form shown holds, not what was typed for another network", async () => {
    page();
    await open("backend");
    fireEvent.change(screen.getByPlaceholderText("db, cache"), { target: { value: "db" } });
    await open("bridge");
    // The default network has no DNS, so no aliases (the daemon refuses them there).
    expect(screen.queryByPlaceholderText("db, cache")).toBeNull();
    fireEvent.change(document.querySelector("select")!, { target: { value: "d00d" } });
    fireEvent.click(screen.getByRole("button", { name: /Connect$/ }));
    await waitFor(() => expect(calls.some(([c]) => c === "network_connect")).toBe(true));
    expect(calls.find(([c]) => c === "network_connect")![1]).toEqual({ id: "n1", body: { container: "d00d", aliases: [] } });
  });

  it("offers no stopped container created for the network, and every running one not on it", async () => {
    page();
    await open("backend");
    expect(choices()).toEqual(["c0ffee", "beef"]);
    await open("bridge");
    expect(choices()).toEqual(["d00d", "beef"]);
  });
});
