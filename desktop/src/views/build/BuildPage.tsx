// "Build": an image from a Containerfile and its context, as `rustlet
// build` makes one. The app packs the context directory (less what its
// .dockerignore excludes) and sends it as it packs; rustletd runs the steps
// and reports each: a RUN's output as it prints it, a cached step, the
// layer a step added. The build goes on while the user is elsewhere in the
// app (session.ts).

import { useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  CircleDashed,
  CircleSlash,
  Eraser,
  Hammer,
  Square,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";

import { PageHeader } from "@/components/common";
import { PullProgress } from "@/components/PullProgress";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/input";
import { Empty, Mono, Spinner } from "@/components/ui/misc";
import { parseAnsi } from "@/lib/ansi";
import { type BuildForm, type BuildState, type BuildStep, displayLine } from "@/lib/build";
import { cn } from "@/lib/cn";
import { bytes, duration, imageName, plural, shortId } from "@/lib/format";
import { useNetworks } from "@/lib/queries";

import { clearBuild, isFinished, startBuild, stopCurrentBuild, useBuildSession } from "./session";

export function BuildPage() {
  const session = useBuildSession();
  const [form, setForm] = useState<BuildForm>(session.form);
  const [error, setError] = useState<string | null>(null);
  const networks = useNetworks();
  const client = useQueryClient();
  const running = session.state != null && !isFinished(session.state);
  const set = <K extends keyof BuildForm>(k: K, v: BuildForm[K]) => setForm((f) => ({ ...f, [k]: v }));

  const submit = () => {
    setError(null);
    if (!form.context.trim()) return;
    try {
      startBuild(form, client);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <div>
      <PageHeader
        title="Build"
        subtitle="An image from a Containerfile and its context directory, as rustlet build makes one."
        actions={
          running ? (
            <Button onClick={stopCurrentBuild} data-testid="build-stop">
              <Square /> Stop
            </Button>
          ) : (
            session.state && (
              <Button onClick={clearBuild}>
                <Eraser /> Clear
              </Button>
            )
          )
        }
      />
      <div className="grid grid-cols-1 items-start gap-4 p-6 xl:grid-cols-[24rem_1fr]">
        <Card>
          <CardHeader title="What to build" />
          <CardContent>
            <form
              className="flex flex-col gap-4"
              onSubmit={(e) => {
                e.preventDefault();
                submit();
              }}
            >
              <Field label="Context directory" hint="Absolute, or from ~/. What its .dockerignore excludes is never sent.">
                <Input value={form.context} onChange={(e) => set("context", e.target.value)} placeholder="~/src/hits" autoFocus name="context" />
              </Field>
              <Field label="Containerfile" hint="Relative to the context; default its Containerfile, else its Dockerfile.">
                <Input value={form.containerfile} onChange={(e) => set("containerfile", e.target.value)} placeholder="Containerfile" name="containerfile" />
              </Field>
              <Field label="Names (-t)" hint="Separated by commas. None: the image is kept unnamed, as <none>.">
                <Input value={form.tags} onChange={(e) => set("tags", e.target.value)} placeholder="hits:latest" name="tags" />
              </Field>
              <Field label="Build arguments" hint="KEY=VALUE, one per line, for the file's ARGs.">
                <Textarea value={form.buildArgs} onChange={(e) => set("buildArgs", e.target.value)} placeholder="PYTHON_VERSION=3.13" rows={2} name="build-args" />
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Target stage" hint="Default: the last.">
                  <Input value={form.target} onChange={(e) => set("target", e.target.value)} placeholder="builder" name="target" />
                </Field>
                <Field label="RUN steps' network">
                  <Select value={form.network} onChange={(e) => set("network", e.target.value)} name="network">
                    <option value="bridge">bridge (default)</option>
                    {(networks.data ?? [])
                      .filter((n) => n.name !== "bridge")
                      .map((n) => (
                        <option key={n.id} value={n.name}>
                          {n.name}
                        </option>
                      ))}
                    <option value="host">host</option>
                    <option value="none">none</option>
                  </Select>
                </Field>
              </div>
              <div className="flex flex-col gap-2">
                <Checkbox checked={form.noCache} onChange={(v) => set("noCache", v)} label="No cache" hint="Run every step again, whatever the cache has." />
                <Checkbox checked={form.pull} onChange={(v) => set("pull", v)} label="Pull base images" hint="Ask the registry what each FROM's tag points at now." />
              </div>
              {error && (
                <p className="bg-destructive/10 text-destructive selectable rounded-md px-3 py-2 text-sm break-words" data-testid="build-form-error">
                  {error}
                </p>
              )}
              <Button type="submit" variant="primary" disabled={running || !form.context.trim()} data-testid="build-submit">
                {running ? <Spinner className="text-primary-foreground" /> : <Hammer />}
                {running ? "Building…" : "Build"}
              </Button>
            </form>
          </CardContent>
        </Card>
        {session.state ? (
          <BuildProgress state={session.state} startedAt={session.startedAt} finishedAt={session.finishedAt} />
        ) : (
          <Card>
            <Empty icon={<Hammer />} title="Nothing built yet">
              Name a directory with a Containerfile. Each step shows here as rustletd runs it, with what a RUN prints.
            </Empty>
          </Card>
        )}
      </div>
    </div>
  );
}

const PHASE: Record<BuildState["phase"], string> = {
  sending: "Sending the context…",
  building: "Building",
  done: "Built",
  error: "Failed",
  stopped: "Stopped",
};

function BuildProgress({ state, startedAt, finishedAt }: { state: BuildState; startedAt?: number; finishedAt?: number }) {
  const step = state.steps.findLast((s) => s.state === "running");
  const took = startedAt != null && finishedAt != null ? ` in ${duration((finishedAt - startedAt) / 1000).toLowerCase()}` : "";
  const multiStage = state.stages.length > 1;
  return (
    <Card data-testid="build-progress" data-phase={state.phase}>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            {state.phase === "done" ? (
              <CheckCircle2 className="text-success size-4" />
            ) : state.phase === "error" ? (
              <XCircle className="text-destructive size-4" />
            ) : state.phase === "stopped" ? (
              <CircleSlash className="text-muted-foreground size-4" />
            ) : (
              <Spinner />
            )}
            {PHASE[state.phase]}
            {state.phase === "building" && step && ` step ${step.step} of ${step.total}`}
            {(state.phase === "done" || state.phase === "error") && took}
          </span>
        }
        description={
          state.context &&
          `Context: ${state.context.files} ${state.context.files === 1 ? "entry" : "entries"} · ${bytes(state.context.bytes)}`
        }
      />
      <CardContent className="flex flex-col gap-3">
        {state.image && (
          <div className="bg-success/10 flex flex-wrap items-center gap-2 rounded-md px-3 py-2 text-sm" data-testid="build-result">
            <span>Image</span>
            <Link to={`/images/${encodeURIComponent(state.image.names[0] ?? state.image.id)}`} className="text-primary font-medium hover:underline">
              {state.image.names.length ? state.image.names.map(imageName).join(", ") : `${shortId(state.image.id)} (unnamed)`}
            </Link>
            <Mono className="text-muted-foreground text-xs">{shortId(state.image.id)}</Mono>
          </div>
        )}
        {state.error && (
          <p className="bg-destructive/10 text-destructive selectable rounded-md px-3 py-2 text-sm break-words" data-testid="build-error">
            {state.error}
          </p>
        )}
        {state.warnings.length > 0 && (
          <ul className="flex flex-col gap-1 text-sm" data-testid="build-warnings">
            {state.warnings.map((w, i) => (
              <li key={i} className="text-warning flex items-start gap-1.5">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                <span className="break-words">{w}</span>
              </li>
            ))}
          </ul>
        )}
        <ol className="flex flex-col gap-1" data-testid="build-steps">
          {state.steps.map((s, i) => {
            const stage = multiStage && s.stage !== state.steps[i - 1]?.stage ? state.stages.find((st) => st.index === s.stage) : undefined;
            return (
              <li key={s.step}>
                {stage && (
                  <div className="text-muted-foreground mt-2 mb-1 text-xs font-medium tracking-wide uppercase">
                    Stage {stage.name ?? stage.index}
                  </div>
                )}
                <StepRow step={s} />
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}

function StepRow({ step: s }: { step: BuildStep }) {
  // The step under way and one that failed show their output; the rest
  // fold it away until asked.
  const [open, setOpen] = useState<boolean | null>(null);
  const lines = s.output.length + (s.partial ? 1 : 0);
  const shown = open ?? (s.state === "running" || s.state === "failed");
  const showPull = s.pull && (s.pull.blobs.length > 0 || s.pull.phase !== "ready");
  return (
    <div className="rounded-md border" data-testid="build-step" data-step={s.step} data-state={s.state}>
      <button
        type="button"
        className="hover:bg-muted/40 flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm disabled:cursor-default"
        onClick={() => setOpen(!shown)}
        disabled={lines === 0}
        aria-expanded={lines ? shown : undefined}
      >
        <StepIcon state={s.state} />
        <span className="text-muted-foreground w-12 shrink-0 text-xs tabular-nums">
          {s.step}/{s.total}
        </span>
        <Mono className="min-w-0 flex-1 truncate" title={s.instruction}>
          {s.instruction}
        </Mono>
        {s.state === "cached" && <Badge tone="info">cached</Badge>}
        {s.layer && (
          <Badge tone="neutral" title={s.layer}>
            layer {shortId(s.layer)}
          </Badge>
        )}
        {lines > 0 && (
          <span className="text-muted-foreground flex shrink-0 items-center gap-0.5 text-xs">
            {plural(lines + s.dropped, "line")}
            {shown ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />}
          </span>
        )}
      </button>
      {showPull && s.pull && (
        <div className="border-t px-3 py-2">
          <PullProgress state={s.pull} />
        </div>
      )}
      {shown && lines > 0 && <Output step={s} />}
    </div>
  );
}

function StepIcon({ state }: { state: BuildStep["state"] }) {
  switch (state) {
    case "running":
      return <Spinner className="size-3.5 shrink-0" />;
    case "cached":
    case "done":
      return <CheckCircle2 className="text-success size-3.5 shrink-0" />;
    case "failed":
      return <XCircle className="text-destructive size-3.5 shrink-0" />;
    case "stopped":
      return <CircleDashed className="text-muted-foreground size-3.5 shrink-0" />;
  }
}

/** A RUN step's output, coloured as a terminal would (lib/ansi.ts), the
 * colours carried from one line to the next. */
function Output({ step }: { step: BuildStep }) {
  const style = { style: {} };
  const lines = step.partial ? [...step.output, step.partial] : step.output;
  return (
    <div
      className="selectable max-h-96 overflow-auto border-t bg-[oklch(0.16_0.005_286)] px-3 py-2 font-mono text-[12px] leading-5 text-[oklch(0.92_0_0)]"
      data-testid="build-output"
    >
      {step.dropped > 0 && <div className="text-[oklch(0.6_0_0)]">… {plural(step.dropped, "earlier line")} not kept</div>}
      {lines.map((l, i) => {
        const spans = parseAnsi(displayLine(l.text), style);
        return (
          <div key={i} className={cn("break-all whitespace-pre-wrap", l.stream === "stderr" && "bg-red-500/8")}>
            {spans.map((sp, j) => (
              <span
                key={j}
                style={{
                  color: sp.fg,
                  background: sp.bg,
                  fontWeight: sp.bold ? 600 : undefined,
                  opacity: sp.dim ? 0.7 : undefined,
                  fontStyle: sp.italic ? "italic" : undefined,
                  textDecoration: sp.underline ? "underline" : undefined,
                }}
              >
                {sp.text}
              </span>
            ))}
            {/* An empty line keeps its height. */}
            {spans.length === 0 && " "}
          </div>
        );
      })}
    </div>
  );
}
