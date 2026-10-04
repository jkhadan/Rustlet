// A load's progress, folded from its events (`LoadEvent`: a `blob` per
// blob of the archive stored, checked against its digest; a `loaded` per
// image, once its layers are unpacked). rustlet-client makes the daemon's
// `error` event the stream's error, which arrives here as `failLoad`.

import type { LoadEvent } from "@/bindings";

export interface LoadState {
  phase: "loading" | "done" | "error";
  /** Blobs stored, and their bytes; `existed`: already in the store. */
  blobs: number;
  bytes: number;
  existed: number;
  /** Images loaded: a name each, or none (kept unnamed, by its id). */
  images: { id: string; name: string | null }[];
  error?: string;
}

export function initialLoad(): LoadState {
  return { phase: "loading", blobs: 0, bytes: 0, existed: 0, images: [] };
}

export function loadReducer(s: LoadState, e: LoadEvent): LoadState {
  switch (e.status) {
    case "blob":
      return { ...s, blobs: s.blobs + 1, bytes: s.bytes + e.size, existed: s.existed + (e.existed ? 1 : 0) };
    case "loaded":
      return { ...s, images: [...s.images, { id: e.id, name: e.name }] };
    case "error":
      return failLoad(s, e.message);
  }
}

/** The stream ended: everything in the archive is loaded. */
export function endLoad(s: LoadState): LoadState {
  return s.phase === "loading" ? { ...s, phase: "done" } : s;
}

export function failLoad(s: LoadState, message: string): LoadState {
  return { ...s, phase: "error", error: message };
}
