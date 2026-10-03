// "Run a container": what `rustlet run -d` does, as a form. The flow is the
// CLI's: create; if the image isn't there (`no_such_image`), pull it,
// showing its progress, and create again; then start.

import { ChevronDown, ChevronRight, Play } from "lucide-react";
import { useState } from "react";
import { useNavigate } from "react-router";
import { toast } from "sonner";

import type { ContainerConfig, RestartPolicyName } from "@/bindings";
import { PullProgress } from "@/components/PullProgress";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/input";
import { Spinner } from "@/components/ui/misc";
import { imageName, splitCommand } from "@/lib/format";
import { api, call, CommandFailed } from "@/lib/ipc";
import { initialPull, pullReducer, type PullState } from "@/lib/pull";
import { useImages, useNetworks } from "@/lib/queries";

interface Form {
  image: string;
  name: string;
  command: string;
  ports: string;
  volumes: string;
  env: string;
  network: string;
  restart: RestartPolicyName;
  tty: boolean;
  autoRemove: boolean;
  readOnly: boolean;
  remap: boolean;
  privileged: boolean;
  memory: string;
  cpus: string;
  pids: string;
  capAdd: string;
  capDrop: string;
  start: boolean;
}

const empty: Form = {
  image: "",
  name: "",
  command: "",
  ports: "",
  volumes: "",
  env: "",
  network: "bridge",
  restart: "no",
  tty: false,
  autoRemove: false,
  readOnly: false,
  remap: false,
  privileged: false,
  memory: "",
  cpus: "",
  pids: "",
  capAdd: "",
  capDrop: "",
  start: true,
};

const lines = (s: string) =>
  s
    .split(/[\n,]/)
    .map((l) => l.trim())
    .filter(Boolean);

/** The form as the API's `ContainerConfig` (ports and volumes parsed by
 * Rust, as the CLI parses them). */
async function toConfig(f: Form): Promise<Partial<ContainerConfig> & { image: string }> {
  const parsed = await call<{ ports: ContainerConfig["ports"]; mounts: ContainerConfig["mounts"] }>("parse_run_options", {
    ports: lines(f.ports),
    volumes: lines(f.volumes),
  });
  const number = (s: string, what: string) => {
    if (!s.trim()) return null;
    const n = Number(s);
    if (!Number.isFinite(n) || n < 0) throw new Error(`${what}: ${s} is not a number`);
    return n;
  };
  const memory = number(f.memory, "memory");
  return {
    image: f.image.trim(),
    name: f.name.trim() || null,
    cmd: f.command.trim() ? splitCommand(f.command) : [],
    env: f.env
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean),
    ports: parsed.ports,
    mounts: parsed.mounts,
    network: f.network,
    restart: { name: f.restart, max_retries: 0 },
    tty: f.tty,
    open_stdin: f.tty,
    auto_remove: f.autoRemove,
    read_only: f.readOnly,
    userns: f.remap ? "remap" : "host",
    privileged: f.privileged,
    memory: memory == null ? null : Math.round(memory * 1024 * 1024),
    cpus: number(f.cpus, "CPUs"),
    pids_limit: number(f.pids, "PIDs limit"),
    cap_add: lines(f.capAdd),
    cap_drop: lines(f.capDrop),
  };
}

export function RunDialog({ open, onOpenChange, image }: { open: boolean; onOpenChange: (o: boolean) => void; image?: string }) {
  const [form, setForm] = useState<Form>(() => ({ ...empty, image: image ?? "" }));
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [pull, setPull] = useState<PullState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const images = useImages();
  const networks = useNetworks();
  const navigate = useNavigate();
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

  const reset = () => {
    setForm({ ...empty, image: image ?? "" });
    setPull(null);
    setError(null);
    setBusy(null);
  };

  /** Pulls `reference` with the `missing` policy, showing progress. */
  const pullImage = (reference: string) =>
    new Promise<void>((resolve, reject) => {
      setPull(initialPull(reference));
      api.images
        .pull(reference, "missing", (m) => {
          if (m.type === "items") {
            setPull((s) => m.items.reduce(pullReducer, s ?? initialPull(reference)));
            const last = m.items[m.items.length - 1];
            if (last?.status === "error") reject(new Error(last.message));
          } else if (m.type === "end") resolve();
          else reject(new CommandFailed(m.error));
        })
        .catch(reject);
    });

  const submit = async () => {
    setError(null);
    try {
      setBusy("Checking");
      const config = await toConfig(form);
      if (!config.image) throw new Error("Which image? (alpine, nginx:1.27, …)");
      setBusy("Creating");
      let created;
      try {
        created = await api.containers.create(config);
      } catch (e) {
        if (!(e instanceof CommandFailed && e.kind === "no_such_image")) throw e;
        setBusy("Pulling");
        await pullImage(config.image);
        setBusy("Creating");
        created = await api.containers.create(config);
      }
      for (const w of created.warnings) toast.warning(w);
      if (form.start) {
        setBusy("Starting");
        await api.containers.start(created.id);
      }
      toast.success(`${created.name} ${form.start ? "is running" : "created"}`);
      onOpenChange(false);
      reset();
      if (!form.autoRemove) navigate(`/containers/${created.id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const imageNames = [...new Set((images.data ?? []).flatMap((i) => i.names.map(imageName)))].sort();

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        if (!busy) {
          onOpenChange(o);
          if (!o) reset();
        }
      }}
      title="Run a container"
      description="Create a container from an image and start it, as rustlet run -d does."
      className="w-[min(680px,94vw)]"
      footer={
        <>
          <Checkbox checked={form.start} onChange={(v) => set("start", v)} label="Start it" />
          <div className="flex-1" />
          <Button onClick={() => onOpenChange(false)} disabled={busy != null}>
            Cancel
          </Button>
          <Button variant="primary" onClick={() => void submit()} disabled={busy != null || !form.image.trim()} data-testid="run-submit">
            {busy ? <Spinner className="text-primary-foreground" /> : <Play />}
            {busy ? `${busy}…` : form.start ? "Run" : "Create"}
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
        <div className="grid grid-cols-2 gap-3">
          <Field label="Image" hint="Pulled from Docker Hub if it isn't here yet.">
            <Input
              list="image-names"
              value={form.image}
              onChange={(e) => set("image", e.target.value)}
              placeholder="alpine, nginx:1.27, ghcr.io/…"
              autoFocus
              name="image"
            />
            <datalist id="image-names">
              {imageNames.map((n) => (
                <option key={n} value={n} />
              ))}
            </datalist>
          </Field>
          <Field label="Name" hint="Generated if left empty.">
            <Input value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="web" name="name" />
          </Field>
        </div>
        <Field label="Command" hint="Replaces the image's CMD; quoted like a shell's.">
          <Input
            value={form.command}
            onChange={(e) => set("command", e.target.value)}
            placeholder={`sh -c "while true; do date; sleep 1; done"`}
            className="font-mono text-xs"
            name="command"
          />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Ports (-p)" hint="One per line: 8080:80, 127.0.0.1::53/udp">
            <Textarea value={form.ports} onChange={(e) => set("ports", e.target.value)} placeholder="8080:80" rows={2} />
          </Field>
          <Field label="Volumes (-v)" hint="data:/data, /srv/www:/usr/share/nginx/html:ro">
            <Textarea value={form.volumes} onChange={(e) => set("volumes", e.target.value)} placeholder="data:/data" rows={2} />
          </Field>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Network">
            <Select value={form.network} onChange={(e) => set("network", e.target.value)}>
              <option value="bridge">bridge (default)</option>
              {(networks.data ?? [])
                .filter((n) => n.name !== "bridge")
                .map((n) => (
                  <option key={n.id} value={n.name}>
                    {n.name}
                  </option>
                ))}
              <option value="host">host (the host's network)</option>
              <option value="none">none (loopback only)</option>
            </Select>
          </Field>
          <Field label="Restart policy">
            <Select value={form.restart} onChange={(e) => set("restart", e.target.value as RestartPolicyName)}>
              <option value="no">no</option>
              <option value="on-failure">on-failure</option>
              <option value="always">always</option>
              <option value="unless-stopped">unless-stopped</option>
            </Select>
          </Field>
        </div>
        <Field label="Environment" hint="KEY=value, one per line.">
          <Textarea value={form.env} onChange={(e) => set("env", e.target.value)} placeholder="POSTGRES_PASSWORD=secret" rows={2} />
        </Field>
        <div className="grid grid-cols-2 gap-x-6 gap-y-2">
          <Checkbox checked={form.tty} onChange={(v) => set("tty", v)} label="Terminal (-it)" hint="A shell image stays up with one." />
          <Checkbox checked={form.autoRemove} onChange={(v) => set("autoRemove", v)} label="Remove when it exits (--rm)" />
          <Checkbox checked={form.readOnly} onChange={(v) => set("readOnly", v)} label="Read-only root filesystem" />
          <Checkbox
            checked={form.remap}
            onChange={(v) => set("remap", v)}
            label="User namespace (--userns remap)"
            hint="Container root is host uid 1000000."
          />
        </div>
        <button
          type="button"
          className="text-muted-foreground hover:text-foreground flex items-center gap-1 self-start text-xs font-medium"
          onClick={() => setAdvanced((a) => !a)}
        >
          {advanced ? <ChevronDown className="size-3.5" /> : <ChevronRight className="size-3.5" />} Resources and
          privileges
        </button>
        {advanced && (
          <div className="flex flex-col gap-3">
            <div className="grid grid-cols-3 gap-3">
              <Field label="Memory (MiB)">
                <Input value={form.memory} onChange={(e) => set("memory", e.target.value)} placeholder="unlimited" inputMode="numeric" />
              </Field>
              <Field label="CPUs">
                <Input value={form.cpus} onChange={(e) => set("cpus", e.target.value)} placeholder="1.5" inputMode="decimal" />
              </Field>
              <Field label="PIDs limit">
                <Input value={form.pids} onChange={(e) => set("pids", e.target.value)} placeholder="unlimited" inputMode="numeric" />
              </Field>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Add capabilities">
                <Input value={form.capAdd} onChange={(e) => set("capAdd", e.target.value)} placeholder="NET_ADMIN, SYS_PTRACE" />
              </Field>
              <Field label="Drop capabilities">
                <Input value={form.capDrop} onChange={(e) => set("capDrop", e.target.value)} placeholder="ALL" />
              </Field>
            </div>
            <Checkbox
              checked={form.privileged}
              onChange={(v) => set("privileged", v)}
              label="Privileged"
              hint="Every capability and host device, no seccomp: no isolation from host root."
            />
          </div>
        )}
        {pull && <PullProgress state={pull} />}
        {error && (
          <p className="bg-destructive/10 text-destructive selectable rounded-md px-3 py-2 text-sm break-words" data-testid="run-error">
            {error}
          </p>
        )}
        <button type="submit" hidden />
      </form>
    </Dialog>
  );
}
