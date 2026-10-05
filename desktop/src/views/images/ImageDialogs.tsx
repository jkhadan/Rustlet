// The images' simple dialogs: tag, save to a file, load from one. The
// images list follows from the daemon's events (`tag` for each name given,
// `load` for an unnamed image loaded); nothing here updates the cache.

import { CheckCircle2, Save, Tag, Upload, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Mono, Spinner } from "@/components/ui/misc";
import { bytes, imageName, plural, shortId } from "@/lib/format";
import { api } from "@/lib/ipc";
import { endLoad, failLoad, initialLoad, loadReducer, type LoadState } from "@/lib/load";

function ErrorLine({ error, testId }: { error: string | null; testId: string }) {
  if (!error) return null;
  return (
    <p className="bg-destructive/10 text-destructive selectable rounded-md px-3 py-2 text-sm break-words" data-testid={testId}>
      {error}
    </p>
  );
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** `rustlet tag SOURCE TARGET`: another name for the image. */
export function TagDialog({ source, open, onOpenChange }: { source: string; open: boolean; onOpenChange: (o: boolean) => void }) {
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = () => {
    setTarget("");
    setError(null);
    onOpenChange(false);
  };
  const submit = async () => {
    if (!target.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.images.tag(source, target.trim());
      toast.success(`Tagged ${imageName(source)} as ${target.trim()}`);
      close();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog
      open={open}
      onOpenChange={(o) => (o ? onOpenChange(true) : close())}
      title={`Tag ${imageName(source)}`}
      description="Another name for the image. A name another image had moves to this one."
      footer={
        <>
          <Button onClick={close}>Cancel</Button>
          <Button variant="primary" onClick={() => void submit()} disabled={busy || !target.trim()} data-testid="tag-submit">
            {busy ? <Spinner className="text-primary-foreground" /> : <Tag />} Tag
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
        <Field label="New name" hint="name[:tag], with a registry's host first to push it there later.">
          <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="hits:1.0" autoFocus name="target" />
        </Field>
        <ErrorLine error={error} testId="tag-error" />
      </form>
    </Dialog>
  );
}

/** `rustlet save -o FILE`: images into a tar archive (an OCI layout, which
 * `rustlet load` and `docker load` read). */
export function SaveDialog({ names, open, onOpenChange }: { names: string[]; open: boolean; onOpenChange: (o: boolean) => void }) {
  const initial = names.join(", ");
  const [images, setImages] = useState(initial);
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Each opening: a save started in an earlier one reports in a toast, not
  // in this one.
  const opening = useRef(0);
  // The dialog reopens for another image: its names, afresh.
  useEffect(() => {
    if (open) setImages(initial);
  }, [open, initial]);
  const close = () => {
    opening.current++;
    setPath("");
    setError(null);
    setBusy(false);
    onOpenChange(false);
  };
  const submit = async () => {
    const list = images.split(/[\s,]+/).filter(Boolean);
    const file = path.trim();
    if (!list.length || !file) return;
    const mine = opening.current;
    setBusy(true);
    setError(null);
    try {
      const size = await api.images.save(list, file);
      // What was asked for, not a count of images: two names of one image
      // are one image in the archive.
      const asked = list.length === 1 ? (list[0].startsWith("sha256:") ? shortId(list[0]) : imageName(list[0])) : plural(list.length, "name");
      toast.success(`Saved ${asked} (${bytes(size)}) to ${file}`);
      if (opening.current === mine) close();
    } catch (e) {
      if (opening.current === mine) {
        setError(message(e));
        setBusy(false);
      } else {
        toast.error(`Saving to ${file} failed`, { description: message(e) });
      }
    }
  };
  return (
    <Dialog
      open={open}
      // A save under way finishes whether or not the dialog stays: its
      // outcome comes as a toast.
      onOpenChange={(o) => (o ? onOpenChange(true) : close())}
      title="Save to a file"
      description="A tar archive (an OCI image layout) that rustlet load and docker load read."
      footer={
        <>
          <Button onClick={close}>Close</Button>
          <Button variant="primary" onClick={() => void submit()} disabled={busy || !images.trim() || !path.trim()} data-testid="save-submit">
            {busy ? <Spinner className="text-primary-foreground" /> : <Save />}
            {busy ? "Saving…" : "Save"}
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
        <Field label="Images" hint="Names or ids, separated by commas: an image named twice is saved once, with both names.">
          <Input value={images} onChange={(e) => setImages(e.target.value)} name="images" />
        </Field>
        <Field label="File" hint="A new file: absolute, or from ~/. One that exists is never overwritten.">
          <Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="~/hits.tar" autoFocus name="path" />
        </Field>
        <ErrorLine error={error} testId="save-error" />
      </form>
    </Dialog>
  );
}

/** `rustlet load -i FILE`: the images of an archive (`save`'s, or `docker
 * save`'s). */
export function LoadDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [path, setPath] = useState("");
  const [load, setLoad] = useState<LoadState | null>(null);
  // The load the dialog follows. Closing it stops following, not the load:
  // the app goes on sending the file to its end.
  const following = useRef(0);
  const busy = load?.phase === "loading";

  useEffect(
    () => () => {
      following.current++;
    },
    [],
  );

  const start = () => {
    const p = path.trim();
    if (!p) return;
    const mine = ++following.current;
    setLoad(initialLoad());
    api.images
      .load(p, (m) => {
        if (following.current !== mine) return;
        if (m.type === "items") setLoad((s) => m.items.reduce(loadReducer, s ?? initialLoad()));
        else if (m.type === "end") setLoad((s) => endLoad(s ?? initialLoad()));
        else setLoad((s) => failLoad(s ?? initialLoad(), m.error.message));
      })
      .catch((e: unknown) => {
        if (following.current === mine) setLoad((s) => failLoad(s ?? initialLoad(), message(e)));
      });
  };

  const close = () => {
    following.current++;
    setLoad(null);
    setPath("");
    onOpenChange(false);
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => (o ? onOpenChange(true) : close())}
      title="Load from a file"
      description="The images of a tar archive: rustlet save's, or docker save's."
      footer={
        <>
          <Button onClick={close}>Close</Button>
          <Button variant="primary" onClick={start} disabled={busy || !path.trim()} data-testid="load-submit">
            {busy ? <Spinner className="text-primary-foreground" /> : <Upload />}
            {busy ? "Loading…" : "Load"}
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
        <Field label="File" hint="Absolute, or from ~/.">
          <Input value={path} onChange={(e) => setPath(e.target.value)} placeholder="~/hits.tar" autoFocus disabled={busy} name="path" />
        </Field>
        {load && (
          <div className="flex flex-col gap-2 text-sm" data-testid="load-progress" data-phase={load.phase}>
            <span className="flex items-center gap-2 font-medium">
              {load.phase === "done" ? (
                <CheckCircle2 className="text-success size-4" />
              ) : load.phase === "error" ? (
                <XCircle className="text-destructive size-4" />
              ) : (
                <Spinner />
              )}
              {load.phase === "done" ? "Loaded" : load.phase === "error" ? "Failed" : "Loading…"}
              <span className="text-muted-foreground font-normal">
                {plural(load.blobs, "blob")} ({bytes(load.bytes)}){load.existed ? `, ${load.existed} already here` : ""}
              </span>
            </span>
            {load.images.length > 0 && (
              <ul className="flex flex-col gap-1">
                {load.images.map((i) => (
                  <li key={`${i.id}-${i.name}`}>
                    <Link to={`/images/${encodeURIComponent(i.name ?? i.id)}`} className="text-primary hover:underline" onClick={close}>
                      {i.name ? imageName(i.name) : <Mono>{shortId(i.id)} (unnamed)</Mono>}
                    </Link>
                  </li>
                ))}
              </ul>
            )}
            {load.error && <p className="text-destructive selectable break-words">{load.error}</p>}
            {busy && (
              <p className="text-muted-foreground text-xs">Closing this doesn't stop the load: the app sends the file to its end.</p>
            )}
          </div>
        )}
      </form>
    </Dialog>
  );
}
