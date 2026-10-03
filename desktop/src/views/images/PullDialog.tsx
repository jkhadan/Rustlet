import { Download } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { PullProgress } from "@/components/PullProgress";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/misc";
import { api, type StreamHandle } from "@/lib/ipc";
import { failPull, initialPull, pullReducer, type PullState } from "@/lib/pull";

/** A pull the dialog follows; `closed` once it stops following it (the
 * stream may not have been opened yet). */
interface Following {
  closed: boolean;
  handle?: StreamHandle;
}

function unfollow(f: Following | null) {
  if (!f) return;
  f.closed = true;
  f.handle?.cancel();
}

/** `rustlet pull`: ask the registry, download what's missing, unpack. */
export function PullDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [reference, setReference] = useState("");
  const [pull, setPull] = useState<PullState | null>(null);
  const following = useRef<Following | null>(null);
  const busy = pull != null && pull.phase !== "ready" && pull.phase !== "error";

  // Closing the dialog stops following the pull, not the pull: rustletd
  // runs it to the end whether or not a client stays, as it does a stop
  // or a removal.
  useEffect(() => () => unfollow(following.current), []);

  const start = () => {
    const ref = reference.trim();
    if (!ref) return;
    unfollow(following.current);
    const f: Following = { closed: false };
    following.current = f;
    setPull(initialPull(ref));
    api.images
      .pull(ref, "always", (m) => {
        if (f.closed) return;
        if (m.type === "items") {
          setPull((s) => {
            const next = m.items.reduce(pullReducer, s ?? initialPull(ref));
            if (next.phase === "ready" && s?.phase !== "ready") toast.success(`Pulled ${ref}`);
            return next;
          });
        } else if (m.type === "error") {
          setPull((s) => failPull(s ?? initialPull(ref), m.error.message));
        }
      })
      .then((h) => (f.closed ? h.cancel() : (f.handle = h)))
      .catch((e: unknown) => {
        if (!f.closed) setPull((s) => failPull(s ?? initialPull(ref), e instanceof Error ? e.message : String(e)));
      });
  };

  const close = (o: boolean) => {
    if (!o) {
      unfollow(following.current);
      following.current = null;
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
          <Button onClick={() => close(false)}>Close</Button>
          <Button variant="primary" onClick={start} disabled={busy || !reference.trim()} data-testid="pull-submit">
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
          start();
        }}
      >
        <Field label="Image">
          <Input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="nginx:1.27, redis, python:3-slim" autoFocus disabled={busy} name="reference" />
        </Field>
        {pull && <PullProgress state={pull} />}
        {busy && (
          <p className="text-muted-foreground text-xs">
            Closing this doesn't stop the pull: rustletd finishes it, and the image appears in the list when it's done.
          </p>
        )}
      </form>
    </Dialog>
  );
}
