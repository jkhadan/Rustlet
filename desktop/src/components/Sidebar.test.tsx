// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DaemonProvider } from "@/lib/daemon";

import { TooltipProvider } from "./ui/tooltip";

let watch: (m: unknown) => void = () => {};
const answers: Record<string, () => unknown> = {};

vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {
    constructor(onmessage: (m: unknown) => void) {
      watch = onmessage;
    }
  },
  invoke: vi.fn(async (cmd: string) => {
    if (cmd === "daemon_watch") return 1;
    return answers[cmd]?.();
  }),
}));

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), warning: vi.fn() }));
vi.mock("sonner", () => ({ toast }));

const { Sidebar } = await import("./Sidebar");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const denied = { kind: "denied", message: "connect /run/rustlet/rustlet.sock: permission denied" };

async function sidebar(socket: string, error: { kind: string; message: string }) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <DaemonProvider>
        <TooltipProvider>
          <MemoryRouter>
            <Sidebar />
          </MemoryRouter>
        </TooltipProvider>
      </DaemonProvider>
    </QueryClientProvider>,
  );
  act(() => watch({ type: "disconnected", socket, error }));
}

describe("starting the daemon from the sidebar", () => {
  it("says a service that runs but stays out of reach isn't this user's", async () => {
    answers.daemon_start = () => undefined;
    // systemctl start succeeds also when the service already ran.
    answers.daemon_version = () => Promise.reject(denied);
    await sidebar("/run/rustlet/rustlet.sock", denied);
    fireEvent.click(screen.getByRole("button", { name: /Start daemon/ }));
    await waitFor(() => expect(toast.error).toHaveBeenCalled());
    expect(toast.error.mock.calls[0][0]).toMatch(/running, but its socket isn't yours/);
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("says the service runs once its socket answers", async () => {
    answers.daemon_start = () => undefined;
    answers.daemon_version = () => ({ version: "0.6.0", api_version: "1", kernel: "7.0.0" });
    await sidebar("/run/rustlet/rustlet.sock", { kind: "unreachable", message: "connection refused" });
    fireEvent.click(screen.getByRole("button", { name: /Start daemon/ }));
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith("The rustletd service is running"));
  });

  it("isn't offered when RUSTLET_HOST names another daemon's socket", async () => {
    await sidebar("/home/u/dev/rustlet.sock", { kind: "unreachable", message: "connection refused" });
    expect(screen.getByTestId("connection").dataset.state).toBe("disconnected");
    expect(screen.queryByRole("button", { name: /Start daemon/ })).toBeNull();
  });
});
