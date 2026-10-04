import { describe, expect, it } from "vitest";

import type { LoadEvent } from "@/bindings";

import { endLoad, failLoad, initialLoad, loadReducer } from "./load";

const fold = (events: LoadEvent[]) => events.reduce(loadReducer, initialLoad());

describe("load progress", () => {
  it("counts the blobs stored and lists the images loaded, named or not", () => {
    const s = endLoad(
      fold([
        { status: "blob", digest: "sha256:a", size: 100, existed: false },
        { status: "blob", digest: "sha256:b", size: 50, existed: true },
        { status: "loaded", id: "sha256:m", name: "docker.io/library/hits:latest" },
        { status: "loaded", id: "sha256:n", name: null },
      ]),
    );
    expect(s).toEqual({
      phase: "done",
      blobs: 2,
      bytes: 150,
      existed: 1,
      images: [
        { id: "sha256:m", name: "docker.io/library/hits:latest" },
        { id: "sha256:n", name: null },
      ],
    });
  });

  it("a failure is the last word, whether an event or the stream's", () => {
    const s = failLoad(fold([{ status: "blob", digest: "sha256:a", size: 1, existed: false }]), "sha256:b: digest mismatch");
    expect(s).toMatchObject({ phase: "error", error: "sha256:b: digest mismatch", blobs: 1 });
    expect(endLoad(s)).toBe(s);
    expect(fold([{ status: "error", message: "not a tar archive" }])).toMatchObject({ phase: "error", error: "not a tar archive" });
  });
});
