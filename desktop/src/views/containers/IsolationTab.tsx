// The isolation inspector: what actually separates this container from the
// host, read from the kernel while it runs (GET /containers/{id}/isolation,
// crates/rustletd/src/isolation.rs). Each section says what the mechanism
// is for, so the page reads as a tour of chapters 01–10.

import { Search, ShieldAlert, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";

import type { ContainerInspect, Isolation, Namespace } from "@/bindings";
import { ErrorState } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Checkbox, Input } from "@/components/ui/input";
import { Empty, Facts, Meter, Mono, Spinner } from "@/components/ui/misc";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { cn } from "@/lib/cn";
import { bytes } from "@/lib/format";
import { useIsolation } from "@/lib/queries";

const NAMESPACES: Record<string, { title: string; isolates: string }> = {
  mnt: { title: "Mount", isolates: "the mount table: its own root filesystem" },
  uts: { title: "UTS", isolates: "the hostname and NIS domain name" },
  ipc: { title: "IPC", isolates: "System V IPC and POSIX message queues" },
  pid: { title: "PID", isolates: "process ids: its init is PID 1 and sees only its own" },
  net: { title: "Network", isolates: "interfaces, addresses, ports, routes and firewall" },
  cgroup: { title: "Cgroup", isolates: "its view of the cgroup tree (/proc/self/cgroup is 0::/)" },
  user: { title: "User", isolates: "user and group ids: its root can be nobody outside" },
  time: { title: "Time", isolates: "the boot-time and monotonic clocks" },
};

/** Capabilities that come close to root on the host. */
const DANGEROUS = new Set([
  "CAP_SYS_ADMIN",
  "CAP_SYS_MODULE",
  "CAP_SYS_RAWIO",
  "CAP_SYS_PTRACE",
  "CAP_SYS_BOOT",
  "CAP_NET_ADMIN",
  "CAP_DAC_READ_SEARCH",
  "CAP_MAC_ADMIN",
  "CAP_MAC_OVERRIDE",
  "CAP_BPF",
  "CAP_PERFMON",
  "CAP_SYSLOG",
  "CAP_SYS_TIME",
  "CAP_LINUX_IMMUTABLE",
]);

export function IsolationTab({ container, running }: { container: ContainerInspect; running: boolean }) {
  const report = useIsolation(container.id, running);
  if (!running) {
    return (
      <Empty icon={<ShieldCheck />} title="The container isn't running">
        Isolation is what the kernel enforces on its processes: namespaces, capabilities, seccomp, cgroup limits.
        Start it to inspect them.
      </Empty>
    );
  }
  if (report.isPending) {
    return (
      <div className="flex justify-center py-20">
        <Spinner />
      </div>
    );
  }
  if (report.error) return <ErrorState error={report.error} what="the isolation report" />;
  const r = report.data;
  return (
    <div className="flex flex-col gap-4 p-6" data-testid="isolation">
      <Summary r={r} />
      <Namespaces r={r} />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <UserNamespace r={r} />
        <CgroupCard r={r} />
      </div>
      <CapabilitiesCard r={r} />
      <SeccompCard r={r} />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <FilesystemCard r={r} />
        <DevicesCard r={r} />
      </div>
    </div>
  );
}

function Summary({ r }: { r: Isolation }) {
  const own = r.namespaces.filter((n) => !n.shared_with_host).length;
  const userns = r.namespaces.find((n) => n.kind === "user");
  const items: [string, boolean][] = [
    [`${own} of ${r.namespaces.length} namespaces its own`, own >= 6],
    [userns && !userns.shared_with_host ? "user namespace: root is unprivileged outside" : "no user namespace: root is host root", !!userns && !userns.shared_with_host],
    [`${r.capabilities.bounding.length} of ${r.capabilities.known.length} capabilities`, r.capabilities.bounding.length < 20],
    [r.seccomp.mode === "filter" ? `seccomp: ${r.seccomp.profile?.allowed.length ?? "?"} system calls allowed` : `seccomp: ${r.seccomp.mode}`, r.seccomp.mode === "filter"],
    [r.seccomp.no_new_privs ? "no_new_privs" : "setuid binaries work", r.seccomp.no_new_privs],
    [r.filesystem.read_only ? "read-only root" : "writable root", r.filesystem.read_only],
  ];
  return (
    <Card className="flex flex-wrap items-center gap-2 p-4">
      <span className="mr-2 text-sm font-semibold">
        PID <Mono>{r.pid}</Mono> on the host
      </span>
      {items.map(([text, good]) => (
        <Badge key={text} tone={good ? "success" : "warning"} className="py-1">
          {good ? <ShieldCheck className="size-3.5" /> : <ShieldAlert className="size-3.5" />}
          {text}
        </Badge>
      ))}
    </Card>
  );
}

function NsState({ ns }: { ns: Namespace }) {
  if (ns.shared_with_host) return <Badge tone="warning">the host's</Badge>;
  if (ns.shared_with.length) return <Badge tone="info">shared with {ns.shared_with.join(", ")}</Badge>;
  return <Badge tone="success">its own</Badge>;
}

function Namespaces({ r }: { r: Isolation }) {
  return (
    <Card>
      <CardHeader
        title="Namespaces"
        description="Two processes share a namespace when their /proc/<pid>/ns links name the same inode. Compared here with the daemon's own (the host's) and every other running container's."
      />
      <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4" data-testid="namespaces">
        {r.namespaces.map((ns) => (
          <div
            key={ns.kind}
            className={cn("flex flex-col gap-1.5 rounded-md border p-3", ns.shared_with_host && "border-warning/50 bg-warning/5")}
            data-kind={ns.kind}
            data-shared-with-host={ns.shared_with_host}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium">
                {NAMESPACES[ns.kind]?.title ?? ns.kind} <Mono className="text-muted-foreground">{ns.kind}</Mono>
              </span>
              <NsState ns={ns} />
            </div>
            <p className="text-muted-foreground text-xs">{NAMESPACES[ns.kind]?.isolates}</p>
            <div className="text-muted-foreground mt-auto flex flex-wrap items-center gap-x-2 text-xs">
              <Mono>
                {ns.kind}:[{ns.inode}]
              </Mono>
              <span>·</span>
              <span>{ns.mode === "new" ? "made for it" : ns.mode === "join" ? "joined" : "inherited"}</span>
            </div>
            {ns.path && <Mono className="text-muted-foreground truncate text-[11px]">{ns.path}</Mono>}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function UserNamespace({ r }: { r: Isolation }) {
  const c = r.credentials;
  return (
    <Card>
      <CardHeader title="User and group ids" description="What its root is outside: the user namespace's id maps." />
      <CardContent className="flex flex-col gap-4">
        <Facts
          rows={[
            ["Runs as", <Mono key="u">uid {c.uid}, gid {c.gid}{c.additional_gids.length ? `, groups ${c.additional_gids.join(",")}` : ""}</Mono>],
            ["On the host", <Mono key="h" className={c.host_uid === 0 ? "text-warning" : undefined}>uid {c.host_uid}, gid {c.host_gid}</Mono>],
            ["oom_score_adj", r.oom_score_adj],
          ]}
        />
        {r.uid_map.length ? (
          <Table>
            <thead>
              <tr>
                <Th>map</Th>
                <Th>inside</Th>
                <Th>outside</Th>
                <Th>count</Th>
              </tr>
            </thead>
            <tbody>
              {[...r.uid_map.map((m) => ["uid", m] as const), ...r.gid_map.map((m) => ["gid", m] as const)].map(([k, m], i) => (
                <Tr key={i}>
                  <Td>{k}</Td>
                  <Td><Mono>{m.container_id}</Mono></Td>
                  <Td><Mono>{m.host_id}</Mono></Td>
                  <Td><Mono>{m.size}</Mono></Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="text-muted-foreground text-sm">
            No user namespace of its own: its ids are the host's, so its root is the host's root, held back only by the
            other mechanisms on this page. Run it with <Mono>--userns remap</Mono> to map root to an unprivileged id.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function CgroupCard({ r }: { r: Isolation }) {
  const g = r.cgroup;
  const cpus = g.cpu_quota != null ? g.cpu_quota / g.cpu_period : null;
  return (
    <Card>
      <CardHeader title="Cgroup limits" description={<Mono className="break-all">{g.path}</Mono>} />
      <CardContent className="flex flex-col gap-4">
        <Usage label="Memory" value={bytes(g.memory_current)} limit={g.memory_max != null ? bytes(g.memory_max) : null} share={[g.memory_current, g.memory_max]} />
        {g.swap_max != null && g.swap_max !== 0 && (
          <Usage label="Swap" value={bytes(g.swap_current ?? 0)} limit={bytes(g.swap_max)} share={[g.swap_current ?? 0, g.swap_max]} />
        )}
        <Usage label="Processes" value={String(g.pids_current)} limit={g.pids_max != null ? String(g.pids_max) : null} share={[g.pids_current, g.pids_max]} />
        <Facts
          rows={[
            ["CPU", cpus != null ? `${cpus.toFixed(2)} CPUs (${g.cpu_quota} µs per ${g.cpu_period} µs)` : "unlimited"],
            ["CPU weight", g.cpu_weight ?? "–"],
            ["CPU time used", `${(g.cpu_usage_usec / 1e6).toFixed(2)} s`],
            ["OOM kills", g.oom_kills],
          ]}
        />
      </CardContent>
    </Card>
  );
}

function Usage({ label, value, limit, share }: { label: string; value: string; limit: string | null; share: [number, number | null] }) {
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex justify-between text-sm">
        <span>{label}</span>
        <span className="tabular-nums">
          {value} <span className="text-muted-foreground">/ {limit ?? "no limit"}</span>
        </span>
      </div>
      <Meter value={share[0]} max={share[1]} />
    </div>
  );
}

function CapabilitiesCard({ r }: { r: Isolation }) {
  const [held, setHeld] = useState(true);
  const c = r.capabilities;
  const sets = useMemo(
    () => ({
      bounding: new Set(c.bounding),
      permitted: new Set(c.permitted),
      effective: new Set(c.effective),
      inheritable: new Set(c.inheritable),
      ambient: new Set(c.ambient),
    }),
    [c],
  );
  const rows = held ? c.known.filter((k) => sets.bounding.has(k) || sets.permitted.has(k)) : c.known;
  const columns = ["bounding", "permitted", "effective", "inheritable", "ambient"] as const;
  return (
    <Card>
      <CardHeader
        title="Capabilities"
        description={`${c.bounding.length} of ${c.known.length} in its bounding set, the ceiling for anything it or its children can gain (/proc/<pid>/status).`}
        actions={<Checkbox checked={held} onChange={setHeld} label="Only those it holds" />}
      />
      <CardContent className="p-0">
        <Table data-testid="capabilities">
          <thead>
            <tr>
              <Th className="pl-4">Capability</Th>
              {columns.map((col) => (
                <Th key={col} className="text-center capitalize">
                  {col}
                </Th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <Td colSpan={6} className="text-muted-foreground pl-4">
                  None: even its root can do nothing a capability guards.
                </Td>
              </tr>
            )}
            {rows.map((cap) => (
              <Tr key={cap}>
                <Td className="pl-4">
                  <Mono className={cn(DANGEROUS.has(cap) && sets.bounding.has(cap) && "text-destructive font-semibold")}>{cap}</Mono>
                </Td>
                {columns.map((col) => (
                  <Td key={col} className="text-center">
                    {sets[col].has(cap) ? <span className="bg-success inline-block size-2 rounded-full" /> : <span className="text-muted-foreground/40">·</span>}
                  </Td>
                ))}
              </Tr>
            ))}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}

function SeccompCard({ r }: { r: Isolation }) {
  const [filter, setFilter] = useState("");
  const s = r.seccomp;
  const p = s.profile;
  const f = filter.trim().toLowerCase();
  const allowed = p ? p.allowed.filter((n) => n.includes(f)) : [];
  return (
    <Card>
      <CardHeader
        title="Seccomp"
        description="A BPF program the kernel runs on every system call; what the profile doesn't allow fails before it does anything."
        actions={
          <span className="flex items-center gap-2">
            <Badge tone={s.mode === "filter" ? "success" : "warning"}>{s.mode}</Badge>
            {s.filters > 0 && <Badge>{s.filters} filter{s.filters === 1 ? "" : "s"}</Badge>}
            <Badge tone={s.no_new_privs ? "success" : "neutral"}>no_new_privs {s.no_new_privs ? "on" : "off"}</Badge>
          </span>
        }
      />
      <CardContent className="flex flex-col gap-4">
        {!p ? (
          <p className="text-muted-foreground text-sm">
            No profile: every system call reaches the kernel (<Mono>seccomp=unconfined</Mono> or <Mono>--privileged</Mono>).
          </p>
        ) : (
          <>
            <Facts
              rows={[
                ["Default action", <Mono key="d">{p.default_action}{p.default_errno != null ? ` (errno ${p.default_errno})` : ""}</Mono>],
                ["Architectures", <Mono key="a">{p.architectures.join(", ")}</Mono>],
                ["Allowed", `${p.allowed.length} calls outright, ${p.conditional.length} with conditions on their arguments`],
              ]}
            />
            <div className="relative w-64">
              <Search className="text-muted-foreground pointer-events-none absolute top-2 left-2.5 size-4" />
              <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Find a system call" className="pl-8" />
            </div>
            <div className="flex max-h-48 flex-wrap gap-1 overflow-y-auto">
              {allowed.map((n) => (
                <span key={n} className="bg-muted rounded px-1.5 py-0.5 font-mono text-[11px]">
                  {n}
                </span>
              ))}
              {p.conditional
                .filter((n) => n.includes(f))
                .map((n) => (
                  <span key={n} className="bg-info/15 text-info rounded px-1.5 py-0.5 font-mono text-[11px]" title="allowed with some arguments only">
                    {n}*
                  </span>
                ))}
              {f && allowed.length === 0 && !p.conditional.some((n) => n.includes(f)) && (
                <span className="text-muted-foreground text-sm">
                  Not allowed: it fails with the default action.
                </span>
              )}
            </div>
            {p.other.length > 0 && (
              <Table>
                <thead>
                  <tr>
                    <Th>Other rules</Th>
                    <Th>Action</Th>
                  </tr>
                </thead>
                <tbody>
                  {p.other.map((rule, i) => (
                    <Tr key={i}>
                      <Td><Mono>{rule.names.join(", ")}</Mono></Td>
                      <Td>
                        <Mono>
                          {rule.action}
                          {rule.errno != null && ` (errno ${rule.errno})`}
                          {rule.conditional && " with conditions"}
                        </Mono>
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function FilesystemCard({ r }: { r: Isolation }) {
  const fs = r.filesystem;
  return (
    <Card>
      <CardHeader title="Filesystem" description="Its root, and the parts of /proc and /sys it can't see or change." />
      <CardContent className="flex flex-col gap-4">
        <Facts
          rows={[
            ["Root", <Mono key="r" className="break-all">{fs.rootfs}</Mono>],
            ["Root writable", fs.read_only ? "no (read-only)" : "yes (its overlay's upper layer)"],
          ]}
        />
        <PathList title="Masked (unreadable)" paths={fs.masked_paths} />
        <PathList title="Read-only" paths={fs.readonly_paths} />
        <details>
          <summary className="cursor-pointer text-sm font-medium">{fs.mounts.length} mounts</summary>
          <Table className="mt-2">
            <thead>
              <tr>
                <Th>Destination</Th>
                <Th>Type</Th>
                <Th>Options</Th>
              </tr>
            </thead>
            <tbody>
              {fs.mounts.map((m, i) => (
                <Tr key={i}>
                  <Td><Mono>{m.destination}</Mono></Td>
                  <Td>{m.kind}</Td>
                  <Td className="text-muted-foreground text-xs">{m.options.join(",")}</Td>
                </Tr>
              ))}
            </tbody>
          </Table>
        </details>
      </CardContent>
    </Card>
  );
}

function PathList({ title, paths }: { title: string; paths: string[] }) {
  return (
    <div className="flex flex-col gap-1.5">
      <span className="text-sm">{title}</span>
      {paths.length ? (
        <div className="flex flex-wrap gap-1">
          {paths.map((p) => (
            <span key={p} className="bg-muted rounded px-1.5 py-0.5 font-mono text-[11px]">
              {p}
            </span>
          ))}
        </div>
      ) : (
        <span className="text-muted-foreground text-xs">none</span>
      )}
    </div>
  );
}

function DevicesCard({ r }: { r: Isolation }) {
  return (
    <Card>
      <CardHeader
        title="Devices"
        description="The cgroup's eBPF device filter: each access is decided by the last rule that matches it; none matching means EPERM."
      />
      <CardContent className="p-0">
        <Table>
          <thead>
            <tr>
              <Th className="pl-4">Rule</Th>
              <Th>Device</Th>
              <Th>Access</Th>
              <Th>From</Th>
            </tr>
          </thead>
          <tbody>
            {r.devices.map((d, i) => (
              <Tr key={i}>
                <Td className="pl-4">
                  <Badge tone={d.allow ? "success" : "destructive"}>{d.allow ? "allow" : "deny"}</Badge>
                </Td>
                <Td>
                  <Mono>
                    {d.kind} {d.major ?? "*"}:{d.minor ?? "*"} {deviceName(d.kind, d.major, d.minor)}
                  </Mono>
                </Td>
                <Td><Mono>{d.access}</Mono></Td>
                <Td className="text-muted-foreground text-xs">{d.origin === "default" ? "runtime default" : d.origin === "node" ? "mknod of a node" : "configuration"}</Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </CardContent>
    </Card>
  );
}

function deviceName(kind: string, major: number | null, minor: number | null): string {
  if (kind !== "c") return "";
  const known: Record<string, string> = {
    "1:3": "/dev/null",
    "1:5": "/dev/zero",
    "1:7": "/dev/full",
    "1:8": "/dev/random",
    "1:9": "/dev/urandom",
    "5:0": "/dev/tty",
    "5:2": "/dev/ptmx",
    "10:229": "/dev/fuse",
    "10:200": "/dev/net/tun",
  };
  if (major === 136 && minor == null) return "/dev/pts/*";
  return known[`${major}:${minor}`] ?? "";
}
