import { Eraser, Link2, Network as NetworkIcon, Plus, Trash2, Unlink } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router";
import { toast } from "sonner";

import type { Network } from "@/bindings";
import { attempt, ErrorState, PageHeader, useConfirm } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Dialog } from "@/components/ui/dialog";
import { Checkbox, Field, Input, Select } from "@/components/ui/input";
import { Empty, Facts, Mono, Spinner } from "@/components/ui/misc";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Tooltip } from "@/components/ui/tooltip";
import { cn } from "@/lib/cn";
import { useNow } from "@/lib/daemon";
import { ago, isLive } from "@/lib/format";
import { api } from "@/lib/ipc";
import { useContainers, useNetworks } from "@/lib/queries";

import { TopologyGraph } from "./TopologyGraph";

export function NetworksPage() {
  const networks = useNetworks();
  const containers = useContainers(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [dialog, ask] = useConfirm();
  const now = useNow();
  const current = networks.data?.find((n) => n.id === selected) ?? null;

  const remove = async (n: Network) => {
    const ok = await ask({ title: `Remove network ${n.name}?`, body: `Its bridge ${n.bridge} and firewall rules go with it.`, confirm: "Remove", destructive: true });
    if (ok && (await attempt(`Removing ${n.name} failed`, () => api.networks.remove(n.id)))) setSelected(null);
  };

  const prune = async () => {
    const ok = await ask({ title: "Remove unused networks?", body: "Every user-defined network no container uses.", confirm: "Remove", destructive: true });
    if (!ok) return;
    try {
      const r = await api.networks.prune();
      toast.success(r.deleted.length ? `Removed ${r.deleted.join(", ")}` : "Nothing to remove");
    } catch (e) {
      toast.error("Prune failed", { description: e instanceof Error ? e.message : String(e) });
    }
  };

  return (
    <div>
      {dialog}
      <PageHeader
        title="Networks"
        subtitle="Each network is a Linux bridge with its own subnet; a container has a veth pair on each of its networks."
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
      <div className="flex flex-col gap-4 px-6 py-4">
        {networks.isPending || containers.isPending ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : networks.error ? (
          <ErrorState error={networks.error} what="networks" />
        ) : (
          <>
            <Card className="overflow-hidden">
              <CardHeader
                title="Topology"
                description="Running containers and the networks they are on. Click a network for its details, a container for its page."
              />
              <TopologyGraph networks={networks.data} containers={containers.data ?? []} selected={selected} onSelect={setSelected} />
            </Card>
            {current && <NetworkDetail key={current.id} network={current} onRemove={() => void remove(current)} />}
            {networks.data.length === 0 ? (
              <Empty icon={<NetworkIcon />} title="No networks" />
            ) : (
              <div className="bg-card overflow-hidden rounded-lg border">
                <Table data-testid="networks-table">
                  <thead>
                    <tr>
                      <Th>Name</Th>
                      <Th>Subnet</Th>
                      <Th>Gateway</Th>
                      <Th>Bridge</Th>
                      <Th>Features</Th>
                      <Th>Containers</Th>
                      <Th>Created</Th>
                      <Th className="w-0" />
                    </tr>
                  </thead>
                  <tbody>
                    {networks.data.map((n) => (
                      <Tr
                        key={n.id}
                        className={cn("cursor-pointer", n.id === selected && "bg-primary/5")}
                        onClick={() => setSelected(n.id === selected ? null : n.id)}
                        data-testid="network-row"
                        data-name={n.name}
                      >
                        <Td className="font-medium">{n.name}</Td>
                        <Td>
                          <Mono>{n.subnet}</Mono>
                          {n.subnet6 && <Mono className="text-muted-foreground block">{n.subnet6}</Mono>}
                        </Td>
                        <Td>
                          <Mono>{n.gateway}</Mono>
                        </Td>
                        <Td>
                          <Mono className="text-muted-foreground">{n.bridge}</Mono>
                        </Td>
                        <Td>
                          <span className="flex gap-1">
                            {n.dns && <Badge tone="info">DNS</Badge>}
                            {n.ipv6 && <Badge tone="info">IPv6</Badge>}
                            {n.internal && <Badge tone="warning">internal</Badge>}
                          </span>
                        </Td>
                        <Td className="tabular-nums">{n.containers.length}</Td>
                        <Td className="text-muted-foreground whitespace-nowrap">{ago(n.created, now)}</Td>
                        <Td onClick={(e) => e.stopPropagation()}>
                          {n.name !== "bridge" && (
                            <Tooltip content={n.containers.length ? "Running containers use it" : "Remove"}>
                              <span>
                                <Button size="icon-sm" variant="ghost" disabled={n.containers.length > 0} onClick={() => void remove(n)} aria-label="Remove">
                                  <Trash2 />
                                </Button>
                              </span>
                            </Tooltip>
                          )}
                        </Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </div>
            )}
          </>
        )}
      </div>
      <CreateNetwork open={creating} onOpenChange={setCreating} />
    </div>
  );
}

/** A network, its containers and a form to connect another. Keyed by the
 * network: what was typed for one isn't sent to the next. */
function NetworkDetail({ network: n, onRemove }: { network: Network; onRemove: () => void }) {
  const containers = useContainers(true);
  const [target, setTarget] = useState("");
  const [alias, setAlias] = useState("");
  const [busy, setBusy] = useState(false);
  // `network connect` takes a container whose first network is a bridge
  // network (the default or a user-defined one), running or not; not one
  // on this network already. A running one is if it has an endpoint here;
  // a stopped one has none, but is if it was created for this network.
  // (One connected to it while stopped looks like any other here: the
  // daemon refuses it, and says so.)
  const candidates = (containers.data ?? []).filter(
    (c) =>
      !n.containers.some((e) => e.container_id === c.id) &&
      (isLive(c) || (c.network_mode !== n.name && c.network_mode !== n.id)) &&
      c.network_mode !== "host" &&
      c.network_mode !== "none" &&
      !c.network_mode.startsWith("container:"),
  );

  const connect = async () => {
    if (!target) return;
    setBusy(true);
    // The default network has no DNS, and so no alias field: the daemon
    // refuses aliases there.
    const aliases = n.dns ? alias.split(/[\s,]+/).filter(Boolean) : [];
    const ok = await attempt(`Connecting to ${n.name} failed`, () => api.networks.connect(n.id, { container: target, aliases }));
    setBusy(false);
    if (ok) {
      setTarget("");
      setAlias("");
    }
  };

  return (
    <Card>
      <CardHeader
        title={`Network ${n.name}`}
        description={n.name === "bridge" ? "The default network: no DNS between its containers, as with Docker's." : n.internal ? "Internal: no way out, no published ports." : "Containers on it find each other by name through the embedded DNS server at 127.0.0.11."}
        actions={
          n.name !== "bridge" && (
            <Button size="sm" onClick={onRemove} disabled={n.containers.length > 0}>
              <Trash2 /> Remove
            </Button>
          )
        }
      />
      <CardContent className="grid grid-cols-1 gap-6 lg:grid-cols-[18rem_1fr]">
        <Facts
          rows={[
            ["ID", <Mono key="i">{n.id.slice(0, 12)}</Mono>],
            ["Subnet", <Mono key="s">{[n.subnet, n.subnet6].filter(Boolean).join(", ")}</Mono>],
            ["Gateway", <Mono key="g">{[n.gateway, n.gateway6].filter(Boolean).join(", ")}</Mono>],
            ["Bridge", <Mono key="b">{n.bridge}</Mono>],
            ["Driver", n.driver],
          ]}
        />
        <div className="flex flex-col gap-3">
          {n.containers.length > 0 ? (
            <Table>
              <thead>
                <tr>
                  <Th>Container</Th>
                  <Th>IPv4</Th>
                  <Th>IPv6</Th>
                  <Th>MAC</Th>
                  <Th>Names</Th>
                  <Th className="w-0" />
                </tr>
              </thead>
              <tbody>
                {n.containers.map((e) => (
                  <Tr key={e.container_id}>
                    <Td>
                      <Link to={`/containers/${e.container_id}`} className="font-medium hover:underline">
                        {e.container_name}
                      </Link>
                    </Td>
                    <Td><Mono>{e.ip_address}</Mono></Td>
                    <Td><Mono>{e.ipv6_address ?? "–"}</Mono></Td>
                    <Td><Mono className="text-muted-foreground">{e.mac_address}</Mono></Td>
                    <Td className="text-muted-foreground text-xs">{e.dns_names.join(", ") || "–"}</Td>
                    <Td>
                      <Tooltip content="Disconnect">
                        <Button
                          size="icon-sm"
                          variant="ghost"
                          aria-label="Disconnect"
                          onClick={() => void attempt(`Disconnecting ${e.container_name} failed`, () => api.networks.disconnect(n.id, { container: e.container_id }))}
                        >
                          <Unlink />
                        </Button>
                      </Tooltip>
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <p className="text-muted-foreground text-sm">No running container is on it.</p>
          )}
          <div className="flex items-end gap-2">
            <Field label="Connect a container" className="w-56">
              <Select value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">Choose…</option>
                {candidates.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} ({c.state.status})
                  </option>
                ))}
              </Select>
            </Field>
            {n.dns && (
              <Field label="Aliases" className="w-44">
                <Input value={alias} onChange={(e) => setAlias(e.target.value)} placeholder="db, cache" />
              </Field>
            )}
            <Button onClick={() => void connect()} disabled={!target || busy}>
              {busy ? <Spinner /> : <Link2 />} Connect
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function CreateNetwork({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [name, setName] = useState("");
  const [subnet, setSubnet] = useState("");
  const [gateway, setGateway] = useState("");
  const [ipv6, setIpv6] = useState(false);
  const [internal, setInternal] = useState(false);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (busy || !name.trim()) return;
    setBusy(true);
    const ok = await attempt("Creating the network failed", () =>
      api.networks.create({ name: name.trim(), subnet: subnet.trim() || null, gateway: gateway.trim() || null, ipv6, internal }),
    );
    setBusy(false);
    if (ok) {
      setName("");
      setSubnet("");
      setGateway("");
      setIpv6(false);
      setInternal(false);
      onOpenChange(false);
    }
  };
  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Create a network"
      description="A bridge of its own, a subnet from 10.89.0.0/16 unless you give one, and DNS between its containers."
      footer={
        <>
          <Button onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="primary" onClick={() => void submit()} disabled={busy || !name.trim()}>
            {busy && <Spinner className="text-primary-foreground" />} Create
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
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="backend" autoFocus />
        </Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Subnet" hint="Optional">
            <Input value={subnet} onChange={(e) => setSubnet(e.target.value)} placeholder="10.89.42.0/24" />
          </Field>
          <Field label="Gateway" hint="Optional">
            <Input value={gateway} onChange={(e) => setGateway(e.target.value)} placeholder="10.89.42.1" />
          </Field>
        </div>
        <Checkbox checked={ipv6} onChange={setIpv6} label="IPv6" hint="A /64 from this machine's unique-local range, NAT66 to the outside." />
        <Checkbox checked={internal} onChange={setInternal} label="Internal" hint="No route out and no published ports: its containers only reach each other." />
      </form>
    </Dialog>
  );
}
