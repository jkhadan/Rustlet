import { Download } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { PullProgress } from "@/components/PullProgress";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/misc";
import { api, type StreamHandle } from "@/lib/ipc";
import { initialPull, pullReducer, type PullState } from "@/lib/pull";

/** `rustlet pull`: ask the registry, download what's missing, unpack. */
export function PullDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [reference, setReference] = useState("");
  const [pull, setPull] = useState<PullState | null>(null);
  const handle = useRef<StreamHandle | null>(null);
  const busy = pull != null && pull.phase !== "ready" && pull.phase !== "error";

  // Closing the dialog cancels a pull under way (its worker stops).
  useEffect(() => () => handle.current?.cancel(), []);

  const start = async () => {
    const ref = reference.trim();
    if (!ref) return;
    setPull(initialPull(ref));
    try {
      handle.current = await api.images.pull(ref, "always", (m) => {
        if (m.type === "items") {
          setPull((s) => {
            const next = m.items.reduce(pullReducer, s ?? initialPull(ref));
            if (next.phase === "ready" && s?.phase !== "ready") toast.success(`Pulled ${ref}`);
            return next;
          });
        } else if (m.type === "error") {
          setPull((s) => ({ ...(s ?? initialPull(ref)), phase: "error", error: m.error.message }));
        }
      });
    } catch (e) {
      setPull((s) => ({ ...(s ?? initialPull(ref)), phase: "error", error: e instanceof Error ? e.message : String(e) }));
    }
  };

  const close = (o: boolean) => {
    if (!o) {
      handle.current?.cancel();
      handle.current = null;
      setPull(null);
      setReference("");
    }
    onOpenChange(o);
  };

  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title="Pull an image"
      description="From Docker Hub unless the name says otherwise (ghcr.io/…, quay.io/…)."
      footer={
        <>
          <Button onClick={() => close(false)}>{pull?.phase === "ready" ? "Close" : "Cancel"}</Button>
          <Button variant="primary" onClick={() => void start()} disabled={busy || !reference.trim()} data-testid="pull-submit">
            {busy ? <Spinner className="text-primary-foreground" /> : <Download />}
            {busy ? "Pulling…" : "Pull"}
          </Button>
        </>
      }
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          void start();
        }}
      >
        <Field label="Image">
          <Input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="nginx:1.27, redis, python:3-slim" autoFocus disabled={busy} name="reference" />
        </Field>
        {pull && <PullProgress state={pull} />}
      </form>
    </Dialog>
  );
}
