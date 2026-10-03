// A pull's progress, folded from its events (`PullEvent`, in the order the
// daemon sends them: resolving, resolved, per blob exists | downloading… →
// downloaded, done, per layer layer_exists | unpacking → unpacked, ready;
// or error at any point). The daemon drops progress a client doesn't keep
// up with, but never `ready` or `error`: those settle every row.

import type { BlobKind, PullEvent } from "@/bindings";

/** `stopped`: cut short by the pull's failure. */
export type BlobState = "waiting" | "downloading" | "downloaded" | "exists" | "stopped";
export type LayerState = "waiting" | "unpacking" | "unpacked" | "exists" | "stopped";

export interface BlobProgress {
  digest: string;
  kind: BlobKind;
  current: number;
  total: number;
  state: BlobState;
}

export interface LayerProgress {
  chainId: string;
  blob?: string;
  state: LayerState;
  /** Unpacked: files and bytes written. */
  entries?: number;
  bytes?: number;
}

export type PullPhase = "resolving" | "downloading" | "unpacking" | "ready" | "error";

export interface PullState {
  reference: string;
  phase: PullPhase;
  manifest?: string;
  platform?: string;
  /** Layers and the config, in the order the daemon first named them. */
  blobs: BlobProgress[];
  layers: LayerProgress[];
  /** Compressed size of the image (`resolved`). */
  size?: number;
  layerCount?: number;
  error?: string;
}

export function initialPull(reference: string): PullState {
  return { reference, phase: "resolving", blobs: [], layers: [] };
}

function upsertBlob(blobs: BlobProgress[], digest: string, f: (b: BlobProgress) => BlobProgress, kind: BlobKind) {
  const i = blobs.findIndex((b) => b.digest === digest);
  const base: BlobProgress = i >= 0 ? blobs[i] : { digest, kind, current: 0, total: 0, state: "waiting" };
  const next = f(base);
  return i >= 0 ? blobs.map((b, j) => (j === i ? next : b)) : [...blobs, next];
}

function upsertLayer(layers: LayerProgress[], chainId: string, f: (l: LayerProgress) => LayerProgress) {
  const i = layers.findIndex((l) => l.chainId === chainId);
  const base: LayerProgress = i >= 0 ? layers[i] : { chainId, state: "waiting" };
  const next = f(base);
  return i >= 0 ? layers.map((l, j) => (j === i ? next : l)) : [...layers, next];
}

export function pullReducer(s: PullState, e: PullEvent): PullState {
  switch (e.status) {
    case "resolving":
      return { ...s, phase: "resolving" };
    case "resolved":
      return {
        ...s,
        phase: "downloading",
        manifest: e.manifest,
        platform: e.platform,
        size: e.size,
        layerCount: e.layers,
      };
    case "exists":
      return {
        ...s,
        phase: "downloading",
        blobs: upsertBlob(s.blobs, e.digest, (b) => ({ ...b, current: e.size, total: e.size, state: "exists" }), e.kind),
      };
    case "downloading":
      return {
        ...s,
        phase: "downloading",
        blobs: upsertBlob(
          s.blobs,
          e.digest,
          (b) => ({ ...b, current: e.current, total: e.total, state: "downloading" }),
          e.kind,
        ),
      };
    case "downloaded":
      return {
        ...s,
        blobs: upsertBlob(s.blobs, e.digest, (b) => ({ ...b, current: e.size, total: e.size, state: "downloaded" }), e.kind),
      };
    case "done":
      return { ...s, manifest: e.manifest };
    case "layer_exists":
      return { ...s, phase: "unpacking", layers: upsertLayer(s.layers, e.chain_id, (l) => ({ ...l, state: "exists" })) };
    case "unpacking":
      return {
        ...s,
        phase: "unpacking",
        layers: upsertLayer(s.layers, e.chain_id, (l) => ({ ...l, blob: e.blob, state: "unpacking" })),
      };
    case "unpacked":
      return {
        ...s,
        layers: upsertLayer(s.layers, e.chain_id, (l) => ({ ...l, state: "unpacked", entries: e.entries, bytes: e.bytes })),
      };
    case "ready":
      // Everything is stored and unpacked, whatever said so went missing.
      return {
        ...s,
        phase: "ready",
        manifest: e.manifest,
        blobs: s.blobs.map((b) => (b.state === "exists" ? b : { ...b, current: b.total, state: "downloaded" })),
        layers: s.layers.map((l) => (l.state === "exists" ? l : { ...l, state: "unpacked" })),
      };
    case "error":
      // Nothing goes on: what was under way stopped where it was.
      return {
        ...s,
        phase: "error",
        error: e.message,
        blobs: s.blobs.map((b) => (b.state === "downloading" || b.state === "waiting" ? { ...b, state: "stopped" } : b)),
        layers: s.layers.map((l) => (l.state === "unpacking" || l.state === "waiting" ? { ...l, state: "stopped" } : l)),
      };
  }
}

/** The pull's stream failed: a `{type: "error"}` message, which is what
 * the daemon's own `error` event arrives as (rustlet-client turns it into
 * a stream error), as does a broken connection. */
export function failPull(s: PullState, message: string): PullState {
  return pullReducer(s, { status: "error", message });
}

/** Download progress of the layers, 0 to 1 (the config is tiny). */
export function downloadShare(s: PullState): number {
  const layers = s.blobs.filter((b) => b.kind === "layer");
  const total = layers.reduce((n, b) => n + b.total, 0);
  if (total === 0) return s.phase === "ready" ? 1 : 0;
  return layers.reduce((n, b) => n + Math.min(b.current, b.total), 0) / total;
}
