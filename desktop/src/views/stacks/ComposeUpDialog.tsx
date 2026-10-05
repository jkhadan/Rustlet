// "Up from file…" and a stack's "Up": `rustlet compose up -d`, its progress
// streamed. The app runs the project (compose is client-side): it loads
// the file, then creates what is missing in dependency order, waiting for
// each dependency's condition. Closing the dialog stops following the up,
// not the up, which the app runs to its end: a project left half up is
// worse than one that comes up unwatched.

import { AlertTriangle, CheckCircle2, CircleDashed, FileUp, Hourglass, Square, XCircle } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/input";
import { Mono, Spinner } from "@/components/ui/misc";
import { cn } from "@/lib/cn";
import { actionState, actionText, composeReducer, endCompose, failCompose, initialCompose, type ComposeState } from "@/lib/compose";
import { api, type StreamHandle } from "@/lib/ipc";
import { downloadShare } from "@/lib/pull";

/** What to bring up: the files (one or more, later ones overriding), and
 * the project's name and directory if known (a stack's labels say). */
export interface UpRequest {
  files: string[];
  projectName: string;
  projectDir: string | null;
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** An up the view follows; `closed` once it no longer does (the stream id
 * may not have come yet). */
interface Following {
  closed: boolean;
  handle?: StreamHandle;
}

/** The up the Stacks view follows: its progress, or why it didn't start
 * (a file that doesn't load). Starting one is an event handler's work,
 * never an effect's (which React runs twice in development). */
export function useComposeUp() {
  const [state, setState] = useState<ComposeState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const following = useRef<Following | null>(null);

  const unfollow = useCallback(() => {
    const f = following.current;
    if (f) {
      f.closed = true;
      // Only the forwarding stops: the up runs on in the app.
      f.handle?.cancel();
    }
    following.current = null;
  }, []);
  useEffect(() => unfollow, [unfollow]);

  const start = useCallback(
    (req: UpRequest) => {
      unfollow();
      const f: Following = { closed: false };
      following.current = f;
      const name = req.projectName.trim();
      setError(null);
      setState(initialCompose());
      api.compose
        .up({ files: req.files, project_name: name || null, project_dir: req.projectDir }, (m) => {
          if (f.closed) return;
          if (m.type === "items") {
            setState((s) => m.items.reduce(composeReducer, s ?? initialCompose()));
          } else if (m.type === "end") {
            setState((s) => endCompose(s ?? initialCompose()));
            toast.success(name ? `${name} is up` : "The project is up");
          } else {
            setState((s) => failCompose(s ?? initialCompose(), m.error.message));
          }
        })
        .then((h) => (f.closed ? h.cancel() : (f.handle = h)))
        .catch((e: unknown) => {
          if (f.closed) return;
          setState(null);
          setError(message(e));
        });
    },
    [unfollow],
  );

  const reset = useCallback(() => {
    unfollow();
    setState(null);
    setError(null);
  }, [unfollow]);

  return { state, error, start, reset };
}

export type ComposeUp = ReturnType<typeof useComposeUp>;

export function ComposeUpDialog({ request, up, onClose }: { request: UpRequest; up: ComposeUp; onClose: () => void }) {
  // A stack brought up from several files shows them; one file, or none
  // yet, is a field.
  const several = request.files.length > 1;
  const [file, setFile] = useState(request.files[0] ?? "");
  const [projectName, setProjectName] = useState(request.projectName);
  const busy = up.state?.phase === "running";

  const submit = () => {
    const files = several ? request.files : [file.trim()];
    if (!files[0]) return;
    // The stack's directory goes with the file its labels name: another
    // file is loaded as a project of its own directory (the project moved).
    const named = several || files[0] === request.files[0];
    up.start({ files, projectName, projectDir: named ? request.projectDir : null });
  };

  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Bring a project up"
      description="As rustlet compose up -d: networks, volumes, images and containers, in dependency order."
      className="w-[min(680px,94vw)]"
      footer={
        <>
          <Button onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={submit} disabled={busy || (!several && !file.trim())} data-testid="compose-up-submit">
            {busy ? <Spinner className="text-primary-foreground" /> : <FileUp />}
            {busy ? "Bringing it up…" : "Up"}
          </Button>
        </>
      }
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        {several ? (
          <Field label="Compose files">
            <span className="flex flex-col">
              {request.files.map((f) => (
                <Mono key={f} className="break-all">
                  {f}
                </Mono>
              ))}
            </span>
          </Field>
        ) : (
          <Field label="Compose file" hint="Absolute, or from ~/. Its directory is the project's: paths and .env are read from there.">
            <Input value={file} onChange={(e) => setFile(e.target.value)} placeholder="~/src/hits/compose.yaml" autoFocus disabled={busy} name="file" />
          </Field>
        )}
        <Field label="Project name" hint="Left empty: the file's name:, else its directory's name.">
          <Input value={projectName} onChange={(e) => setProjectName(e.target.value)} placeholder="hits" disabled={busy} name="project" />
        </Field>
        {up.error && (
          <p className="bg-destructive/10 text-destructive selectable rounded-md px-3 py-2 text-sm break-words" data-testid="compose-up-error">
            {up.error}
          </p>
        )}
        {up.state && <ComposeProgressView state={up.state} />}
        {busy && (
          <p className="text-muted-foreground text-xs">
            Closing this doesn't stop it: the app brings the project up to the end, and its stack shows each container as it starts.
          </p>
        )}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}

/** An up as it goes: a line per resource with what last happened to it,
 * the builds and pulls of services' images, what waited for what. */
export function ComposeProgressView({ state }: { state: ComposeState }) {
  const running = state.phase === "running";
  return (
    <div className="flex flex-col gap-3" data-testid="compose-progress" data-phase={state.phase}>
      <span className="flex items-center gap-2 text-sm font-medium">
        {state.phase === "done" ? (
          <CheckCircle2 className="text-success size-4" />
        ) : state.phase === "error" ? (
          <XCircle className="text-destructive size-4" />
        ) : (
          <Spinner />
        )}
        {state.phase === "done" ? "Up" : state.phase === "error" ? "Failed" : "Bringing it up…"}
      </span>
      {state.error && <p className="text-destructive selectable text-sm break-words">{state.error}</p>}
      {(state.builds.length > 0 || state.pulls.length > 0) && (
        <ul className="flex flex-col gap-1 text-xs" data-testid="compose-images">
          {state.pulls.map((p) => (
            <li key={`pull-${p.service}`} className="flex items-center gap-2">
              <span className="w-28 shrink-0 truncate font-medium">{p.service}</span>
              <span className="text-muted-foreground shrink-0">pull {p.image}</span>
              <div className="bg-muted h-1.5 min-w-16 flex-1 overflow-hidden rounded-full">
                <div className={cn("h-full", p.pull.phase === "error" ? "bg-destructive" : "bg-primary/80")} style={{ width: `${downloadShare(p.pull) * 100}%` }} />
              </div>
              <span className="text-muted-foreground w-20 shrink-0 text-right">{p.pull.phase === "ready" ? "pulled" : p.pull.phase}</span>
            </li>
          ))}
          {state.builds.map(({ service, build }) => {
            const step = build.steps.at(-1);
            return (
              <li key={`build-${service}`} className="flex items-center gap-2">
                <span className="w-28 shrink-0 truncate font-medium">{service}</span>
                <span className="text-muted-foreground shrink-0">build</span>
                <Mono className="text-muted-foreground min-w-0 flex-1 truncate" title={step?.instruction}>
                  {step ? `${step.step}/${step.total} ${step.instruction}` : "sending the context…"}
                </Mono>
                <span className="text-muted-foreground w-20 shrink-0 text-right">
                  {build.phase === "done" ? "built" : build.phase === "error" ? "failed" : build.phase === "stopped" ? "stopped" : "building"}
                </span>
              </li>
            );
          })}
        </ul>
      )}
      {state.resources.length > 0 && (
        <ul className="flex flex-col gap-1 text-sm" data-testid="compose-resources">
          {state.resources.map((r) => {
            const s = actionState(r.action);
            return (
              <li key={`${r.kind}-${r.name}`} className="flex items-center gap-2" data-kind={r.kind} data-name={r.name} data-action={r.action}>
                {s === "done" ? (
                  <CheckCircle2 className="text-success size-3.5 shrink-0" />
                ) : s === "exited" ? (
                  <Square className="text-muted-foreground size-3.5 shrink-0" />
                ) : running ? (
                  <Spinner className="size-3.5 shrink-0" />
                ) : (
                  <CircleDashed className="text-muted-foreground size-3.5 shrink-0" />
                )}
                <span className="text-muted-foreground w-20 shrink-0 capitalize">{r.kind}</span>
                <Mono className="min-w-0 flex-1 truncate">{r.name}</Mono>
                <span className={cn("shrink-0", s === "done" ? "text-success" : "text-muted-foreground")}>{actionText(r.action)}</span>
              </li>
            );
          })}
        </ul>
      )}
      {state.notes.length > 0 && (
        <ul className="text-muted-foreground flex flex-col gap-1 text-xs">
          {state.notes.map((n, i) => (
            <li key={i} className="flex items-start gap-1.5">
              {n.kind === "warning" ? (
                <AlertTriangle className="text-warning mt-0.5 size-3.5 shrink-0" />
              ) : (
                <Hourglass className="mt-0.5 size-3.5 shrink-0" />
              )}
              <span className="break-words">{n.text}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
