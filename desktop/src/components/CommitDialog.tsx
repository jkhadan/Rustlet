// "Commit…": the container's changes as a new image, as `rustlet commit`
// makes one. The images list learns of it from the daemon's events (the
// container's `commit`, and an image `tag` if it was named).

import { GitCommitHorizontal } from "lucide-react";
import { useRef, useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";

import { imageName, shortId } from "@/lib/format";
import { api } from "@/lib/ipc";

import { Button } from "./ui/button";
import { Dialog } from "./ui/dialog";
import { Checkbox, Field, Input } from "./ui/input";
import { Spinner } from "./ui/misc";

export function CommitDialog({
  container,
  live,
  open,
  onOpenChange,
}: {
  /** Its id or name. */
  container: string;
  /** Running or paused: whether pausing it means anything. */
  live: boolean;
  open: boolean;
  onOpenChange: (o: boolean) => void;
}) {
  const [reference, setReference] = useState("");
  const [comment, setComment] = useState("");
  const [pause, setPause] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const close = () => {
    setReference("");
    setComment("");
    setPause(true);
    setError(null);
    onOpenChange(false);
  };

  // One commit at a time: Enter in a field submits the form while the
  // button is already disabled, and a second commit makes a second image,
  // moving the name to it and leaving the first unnamed.
  const committing = useRef(false);
  const submit = async () => {
    if (committing.current) return;
    committing.current = true;
    setBusy(true);
    setError(null);
    try {
      const r = await api.containers.commit({
        container,
        reference: reference.trim() || null,
        comment: comment.trim() || null,
        pause,
      });
      const page = `/images/${encodeURIComponent(r.name ?? r.id)}`;
      toast.success(r.name ? `Committed as ${imageName(r.name)}` : `Committed as image ${shortId(r.id)}`, {
        action: { label: "Open", onClick: () => navigate(page) },
      });
      close();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      committing.current = false;
      setBusy(false);
    }
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => (o ? onOpenChange(true) : !busy && close())}
      title="Commit the container"
      description="Its changes (the files it wrote) on top of its image, as a new image, as rustlet commit does."
      footer={
        <>
          <Button onClick={close} disabled={busy}>
            Cancel
          </Button>
          <Button variant="primary" onClick={() => void submit()} disabled={busy} data-testid="commit-submit">
            {busy ? <Spinner className="text-primary-foreground" /> : <GitCommitHorizontal />}
            {busy ? "Committing…" : "Commit"}
          </Button>
        </>
      }
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label="Image name" hint="Left empty: an unnamed image, listed as <none> until it is removed by its id.">
          <Input value={reference} onChange={(e) => setReference(e.target.value)} placeholder="myapp:snapshot" autoFocus name="reference" />
        </Field>
        <Field label="Comment" hint="The new history entry's (-m).">
          <Input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="installed curl" name="comment" />
        </Field>
        {live && (
          <Checkbox
            checked={pause}
            onChange={setPause}
            label="Pause it while its changes are read"
            hint="Otherwise a file it writes meanwhile may be caught half-way."
          />
        )}
        {error && (
          <p className="bg-destructive/10 text-destructive selectable rounded-md px-3 py-2 text-sm break-words" data-testid="commit-error">
            {error}
          </p>
        )}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
