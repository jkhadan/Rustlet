// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  Channel: class {},
  invoke: vi.fn(async (cmd: string, args: { name?: string }) => {
    if (cmd === "image_inspect") throw { kind: "no_such_image", message: `no such image: ${args.name}` };
    if (cmd === "container_list") return [];
    return null;
  }),
}));

const { ImagePage } = await import("./ImagePage");

afterEach(cleanup);

function page(route: string) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[`/images/${encodeURIComponent(route)}`]}>
        <Routes>
          <Route path="/images/:ref" element={<ImagePage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("an image page whose image the daemon doesn't know", () => {
  it("opened by a name: the name is gone, not necessarily the image", async () => {
    // `rmi alpine:latest` of an image also named alpine:3 only untags it.
    page("docker.io/library/alpine:latest");
    expect(await screen.findByText("No image is named alpine:latest any more")).toBeTruthy();
    expect(screen.queryByText("This image is gone")).toBeNull();
  });

  it("opened by its id: the image is gone", async () => {
    page(`sha256:${"4f".repeat(32)}`);
    expect(await screen.findByText("This image is gone")).toBeTruthy();
  });
});
