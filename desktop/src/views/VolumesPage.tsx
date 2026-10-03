import { Eraser, HardDrive, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";

import type { Volume } from "@/bindings";
import { attempt, CopyButton, ErrorState, PageHeader, useConfirm } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Checkbox, Field, Input } from "@/components/ui/input";
import { Empty, Mono, Spinner } from "@/components/ui/misc";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Tooltip } from "@/components/ui/tooltip";
import { useNow } from "@/lib/daemon";
import { ago, bytes, plural } from "@/lib/format";
import { api } from "@/lib/ipc";
import { useContainers, useVolumes } from "@/lib/queries";

export function VolumesPage() {
  const volumes = useVolumes();
  const containers = useContainers(true);
  const [creating, setCreating] = useState(false);
  const [dialog, ask] = useConfirm();
  const now = useNow();
  const idOf = (name: string) => containers.data?.find((c) => c.name === name)?.id ?? name;

  const remove = async (v: Volume) => {
    const ok = await ask({
      title: `Remove volume ${display(v)}?`,
      body: "Its data is deleted for good.",
      confirm: "Remove",
      destructive: true,
    });
    if (ok) await attempt(`Removing ${display(v)} failed`, () => api.volumes.remove(v.name));
  };

  const prune = async () => {
    let all = false;
    const ok = await ask({
      title: "Remove unused volumes?",
      body: (
        <div className="flex flex-col gap-3">
          <p>Every anonymous volume no container uses is deleted, with its data.</p>
          <PruneAll onChange={(v) => (all = v)} />
        </div>
      ),
      confirm: "Remove",
      destructive: true,
    });
    if (!ok) return;
    try {
      const r = await api.volumes.prune(all);
      toast.success(r.deleted.length ? `Removed ${r.deleted.length} volume${r.deleted.length === 1 ? "" : "s"} (${bytes(r.space_reclaimed)})` : "Nothing to remove");
    } catch (e) {
      toast.error("Prune failed", { description: e instanceof Error ? e.message : String(e) });
    }
  };

  return (
    <div>
      {dialog}
      <PageHeader
        title="Volumes"
        subtitle={volumes.data ? `${plural(volumes.data.length, "volume")} · ${volumes.data.filter((v) => v.containers.length === 0).length} unused` : " "}
        actions={
          <>
            <Button onClick={() => void prune()}>
              <Eraser /> Prune
            </Button>
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus /> Create
            </Button>
          </>
        }
      />
      <div className="px-6 py-4">
        {volumes.isPending ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : volumes.error ? (
          <ErrorState error={volumes.error} what="volumes" />
        ) : volumes.data.length === 0 ? (
          <Empty icon={<HardDrive />} title="No volumes yet">
            A volume keeps data beyond its containers: <code className="font-mono">-v data:/data</code> makes one.
          </Empty>
        ) : (
          <div className="bg-card overflow-hidden rounded-lg border">
            <Table data-testid="volumes-table">
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>Mountpoint</Th>
                  <Th>Created</Th>
                  <Th>Used by</Th>
                  <Th className="w-0" />
                </tr>
              </thead>
              <tbody>
                {volumes.data.map((v) => (
                  <Tr key={v.name} data-testid="volume-row" data-name={v.name}>
                    <Td>
                      <span className="flex items-center gap-2">
                        <Mono className="font-medium">{display(v)}</Mono>
                        {v.anonymous && <Badge>anonymous</Badge>}
                        <CopyButton text={v.name} />
                      </span>
                    </Td>
                    <Td className="max-w-80">
                      <Mono className="text-muted-foreground block truncate" title={v.mountpoint}>
                        {v.mountpoint}
                      </Mono>
                    </Td>
                    <Td className="text-muted-foreground whitespace-nowrap">{ago(v.created, now)}</Td>
                    <Td>
                      {v.containers.length ? (
                        <span className="flex flex-wrap gap-1.5">
                          {v.containers.map((c) => (
                            <Link key={c} to={`/containers/${idOf(c)}`} className="text-primary hover:underline">
                              {c}
                            </Link>
                          ))}
                        </span>
                      ) : (
                        <span className="text-muted-foreground">–</span>
                      )}
                    </Td>
                    <Td>
                      <Tooltip content={v.containers.length ? "In use" : "Remove"}>
                        <span>
                          <Button size="icon-sm" variant="ghost" disabled={v.containers.length > 0} onClick={() => void remove(v)} aria-label="Remove">
                            <Trash2 />
                          </Button>
                        </span>
                      </Tooltip>
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </div>
      <CreateVolume open={creating} onOpenChange={setCreating} />
    </div>
  );
}

function display(v: Volume): string {
  return v.anonymous && v.name.length > 24 ? `${v.name.slice(0, 12)}…` : v.name;
}

function PruneAll({ onChange }: { onChange: (v: boolean) => void }) {
  const [all, setAll] = useState(false);
  return (
    <Checkbox
      checked={all}
      onChange={(v) => {
        setAll(v);
        onChange(v);
      }}
      label="Named volumes too"
      hint="Every volume no container uses, as docker volume prune --all."
    />
  );
}

function CreateVolume({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    const ok = await attempt("Creating the volume failed", () => api.volumes.create({ name: name.trim() || null }));
    setBusy(false);
    if (ok) {
      setName("");
      onOpenChange(false);
    }
  };
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Create a volume"
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" onClick={() => void submit()} disabled={busy}>
            {busy && <Spinner className="text-primary-foreground" />} Create
          </Button>
        </>
      }
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void submit();
        }}
      >
        <Field label="Name" hint="Left empty: an anonymous volume with a generated name.">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="data" autoFocus />
        </Field>
      </form>
    </Dialog>
  );
}
