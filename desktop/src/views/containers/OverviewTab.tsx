import { Link } from "react-router";

import type { ContainerInspect } from "@/bindings";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Facts, Mono } from "@/components/ui/misc";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { useNow } from "@/lib/daemon";
import { ago, bytes, commandText, portsText } from "@/lib/format";

/** `--security-opt` values as rustletd reads them (spec.rs, `check`):
 * `key=value` or `key:value`, the last of a key winning. */
function securityOpts(opts: string[]): Map<string, string> {
  const out = new Map<string, string>();
  for (const opt of opts) {
    const i = opt.search(/[=:]/);
    out.set(i < 0 ? opt : opt.slice(0, i), i < 0 ? "" : opt.slice(i + 1));
  }
  return out;
}

export function OverviewTab({ container: c }: { container: ContainerInspect }) {
  const now = useNow();
  const cfg = c.config;
  const net = c.network;
  const restart =
    cfg.restart.name === "on-failure" && cfg.restart.max_retries
      ? `on-failure:${cfg.restart.max_retries}`
      : cfg.restart.name;
  const opts = securityOpts(cfg.security_opt);
  const security = [
    cfg.privileged && "privileged",
    cfg.userns === "remap" && "user namespace",
    cfg.read_only && "read-only root",
    opts.get("seccomp") === "unconfined" && "seccomp unconfined",
    // Rustlets sets it unless told not to.
    opts.get("no-new-privileges") === "false" && "no-new-privileges off",
    ...cfg.cap_add.map((c) => `+${c}`),
    ...cfg.cap_drop.map((c) => `-${c}`),
  ].filter(Boolean) as string[];

  return (
    <div className="grid grid-cols-1 gap-4 p-6 xl:grid-cols-2">
      <Card>
        <CardHeader title="Process" />
        <CardContent>
          <Facts
            rows={[
              ["Command", <Mono key="c">{commandText(c.command)}</Mono>],
              ["Created", ago(c.created, now)],
              ["Started", c.state.started_at ? ago(c.state.started_at, now) : "never"],
              ...(c.state.finished_at
                ? [["Finished", `${ago(c.state.finished_at, now)}, exit code ${c.state.exit_code ?? "?"}${c.state.oom_killed ? " (OOM-killed)" : ""}`] as [string, string]]
                : []),
              ["Host PID", c.state.pid ?? "–"],
              ["Restart policy", `${restart}${c.state.restart_count ? ` (restarted ${c.state.restart_count}×)` : ""}`],
              ["Hostname", <Mono key="h">{c.hostname}</Mono>],
              ["User", cfg.user ?? "the image's"],
              ...(c.state.error ? [["Error", <span key="e" className="text-destructive selectable">{c.state.error}</span>] as [string, React.ReactNode]] : []),
            ]}
          />
        </CardContent>
      </Card>

      <Card>
        <CardHeader title="Resources and security" />
        <CardContent>
          <Facts
            rows={[
              ["Memory", cfg.memory ? bytes(cfg.memory) : "unlimited"],
              ["CPUs", cfg.cpus ?? "unlimited"],
              ["PIDs", cfg.pids_limit && cfg.pids_limit > 0 ? cfg.pids_limit : "unlimited"],
              ["Cgroup", <Mono key="g" className="break-all">{c.cgroup}</Mono>],
              ["User IDs", c.uid_map ? <Mono key="u">{c.uid_map}</Mono> : "the host's (no user namespace)"],
              [
                "Security",
                security.length ? (
                  <span key="s" className="flex flex-wrap gap-1">
                    {security.map((s) => (
                      <Badge key={s} tone={s === "privileged" ? "destructive" : "neutral"}>
                        {s}
                      </Badge>
                    ))}
                  </span>
                ) : (
                  "defaults"
                ),
              ],
            ]}
          />
          <p className="text-muted-foreground mt-3 text-xs">
            The <span className="font-medium">Isolation</span> tab reads what the kernel enforces while it runs.
          </p>
        </CardContent>
      </Card>

      <Card className="xl:col-span-2">
        <CardHeader title="Network" description={`Mode: ${net.mode}`} />
        <CardContent className="flex flex-col gap-4">
          {net.networks.length > 0 ? (
            <Table>
              <thead>
                <tr>
                  <Th>Network</Th>
                  <Th>Interface</Th>
                  <Th>IPv4</Th>
                  <Th>IPv6</Th>
                  <Th>MAC</Th>
                  <Th>DNS names</Th>
                </tr>
              </thead>
              <tbody>
                {net.networks.map((e) => (
                  <Tr key={e.network}>
                    <Td>
                      <Link to="/networks" className="font-medium hover:underline">
                        {e.network}
                      </Link>
                      {e.default_route && <Badge className="ml-2">default route</Badge>}
                    </Td>
                    <Td>
                      <Mono>{e.interface ?? "–"}</Mono>
                    </Td>
                    <Td>
                      <Mono>{e.ip_address ? `${e.ip_address}/${e.ip_prefix_len}` : "–"}</Mono>
                    </Td>
                    <Td>
                      <Mono>{e.ipv6_address ? `${e.ipv6_address}/${e.ipv6_prefix_len}` : "–"}</Mono>
                    </Td>
                    <Td>
                      <Mono>{e.mac_address ?? "–"}</Mono>
                    </Td>
                    <Td className="text-muted-foreground text-xs">{e.dns_names.join(", ") || "–"}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          ) : (
            <p className="text-muted-foreground text-sm">
              {net.mode === "host"
                ? "The host's network namespace: its interfaces and ports are the host's."
                : net.mode === "none"
                  ? "Only a loopback interface."
                  : net.mode.startsWith("container:")
                    ? `Shares ${net.mode.slice(10)}'s network namespace.`
                    : "Not connected (it gets its addresses when it starts)."}
            </p>
          )}
          {net.ports.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <span className="text-muted-foreground">Published:</span>
              {portsText(net.ports).map((p) => (
                <Badge key={p} tone="info" className="font-mono">
                  {p}
                </Badge>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="xl:col-span-2">
        <CardHeader title="Mounts" />
        <CardContent>
          {c.mounts.length === 0 ? (
            <p className="text-muted-foreground text-sm">No volumes, bind mounts or tmpfs.</p>
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Type</Th>
                  <Th>Source</Th>
                  <Th>Destination</Th>
                  <Th>Mode</Th>
                </tr>
              </thead>
              <tbody>
                {c.mounts.map((m) => (
                  <Tr key={m.destination}>
                    <Td>
                      <Badge>{m.type}</Badge>
                    </Td>
                    <Td>
                      {m.type === "volume" ? (
                        // `inspect` doesn't say which volumes are anonymous
                        // (theirs are 64 hex digits, but a named one's may
                        // be too): the name, whole.
                        <Link to="/volumes" className="hover:underline">
                          <Mono className="break-all">{m.name}</Mono>
                        </Link>
                      ) : (
                        <Mono>{m.source}</Mono>
                      )}
                    </Td>
                    <Td>
                      <Mono>{m.destination}</Mono>
                    </Td>
                    <Td>{m.read_only ? "ro" : "rw"}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
