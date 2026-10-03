import { describe, expect, it } from "vitest";

import type { PullEvent } from "@/bindings";

import { downloadShare, initialPull, pullReducer } from "./pull";

const fold = (events: PullEvent[]) => events.reduce(pullReducer, initialPull("alpine"));

describe("pull progress", () => {
  it("follows a pull from resolving to ready", () => {
    const s = fold([
      { status: "resolving", reference: "alpine" },
      {
        status: "resolved",
        reference: "alpine",
        manifest: "sha256:m",
        repo_digest: "sha256:i",
        platform: "linux/amd64",
        layers: 2,
        size: 300,
      },
      { status: "exists", kind: "config", digest: "sha256:c", size: 10 },
      { status: "downloading", kind: "layer", digest: "sha256:a", current: 50, total: 100 },
      { status: "downloading", kind: "layer", digest: "sha256:b", current: 0, total: 200 },
    ]);
    expect(s.phase).toBe("downloading");
    expect(s.platform).toBe("linux/amd64");
    expect(s.blobs.map((b) => [b.digest, b.state])).toEqual([
      ["sha256:c", "exists"],
      ["sha256:a", "downloading"],
      ["sha256:b", "downloading"],
    ]);
    expect(downloadShare(s)).toBeCloseTo(50 / 300);

    const done = [
      { status: "downloaded", kind: "layer", digest: "sha256:a", size: 100 },
      { status: "downloaded", kind: "layer", digest: "sha256:b", size: 200 },
      { status: "done", reference: "alpine", manifest: "sha256:m" },
      { status: "layer_exists", chain_id: "sha256:x" },
      { status: "unpacking", chain_id: "sha256:y", blob: "sha256:b", size: 200 },
      { status: "unpacked", chain_id: "sha256:y", entries: 12, bytes: 4096, whiteouts: 0, opaque_dirs: 0, skipped_devices: 0 },
      { status: "ready", reference: "alpine", manifest: "sha256:m" },
    ] satisfies PullEvent[];
    const end = done.reduce(pullReducer, s);
    expect(end.phase).toBe("ready");
    expect(downloadShare(end)).toBe(1);
    expect(end.layers).toEqual([
      { chainId: "sha256:x", state: "exists" },
      { chainId: "sha256:y", blob: "sha256:b", state: "unpacked", entries: 12, bytes: 4096 },
    ]);
  });

  it("an image already stored is ready at once", () => {
    const s = fold([
      { status: "resolving", reference: "alpine" },
      { status: "ready", reference: "alpine", manifest: "sha256:m" },
    ]);
    expect(s.phase).toBe("ready");
    expect(downloadShare(s)).toBe(1);
  });

  it("an error ends it", () => {
    const s = fold([{ status: "error", message: "manifest unknown" }]);
    expect(s).toMatchObject({ phase: "error", error: "manifest unknown" });
  });
});
