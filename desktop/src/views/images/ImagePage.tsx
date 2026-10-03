import { ArrowLeft, Layers, Play, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";

import type { ImageInspect } from "@/bindings";
import { attempt, CopyButton, ErrorState, PageHeader, useConfirm } from "@/components/common";
import { JsonView } from "@/components/JsonView";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { Empty, Facts, Mono, Spinner } from "@/components/ui/misc";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { useNow } from "@/lib/daemon";
import { ago, bytes, commandText, imageName, shortId } from "@/lib/format";
import { api, CommandFailed } from "@/lib/ipc";
import { useContainers, useImage } from "@/lib/queries";

import { RunDialog } from "../containers/RunDialog";

/** The parts of an OCI image config this page shows. */
interface OciConfig {
  config?: {
    Env?: string[];
    Cmd?: string[];
    Entrypoint?: string[];
    WorkingDir?: string;
    User?: string;
    ExposedPorts?: Record<string, unknown>;
    Volumes?: Record<string, unknown>;
    Labels?: Record<string, string>;
    StopSignal?: string;
  };
  history?: { created?: string; created_by?: string; empty_layer?: boolean; comment?: string }[];
}

export function ImagePage() {
  const { ref = "" } = useParams();
  const name = decodeURIComponent(ref);
  const image = useImage(name);
  const containers = useContainers(true);
  const [running, setRunning] = useState(false);
  const [dialog, ask] = useConfirm();
  const navigate = useNavigate();
  const now = useNow();

  if (image.isPending) {
    return (
      <div className="flex justify-center py-20">
        <Spinner />
      </div>
    );
  }
  if (image.error) {
    if (image.error instanceof CommandFailed && image.error.kind === "no_such_image") {
      // The page is the route's name: removing one of an image's names
      // leaves the image, under its others. Only an id says it is gone.
      const byId = /^sha256:[0-9a-f]{64}$/.test(name);
      return (
        <Empty icon={<Layers />} title={byId ? "This image is gone" : `No image is named ${imageName(name)} any more`}>
          {byId ? "It was removed. " : "The name was removed; the image may live on under another. "}
          <Link to="/images" className="text-primary hover:underline">
            Back to the images
          </Link>
        </Empty>
      );
    }
    return <ErrorState error={image.error} what="the image" />;
  }
  const i: ImageInspect = image.data;
  const oci = i.config as OciConfig;
  const cfg = oci.config ?? {};
  const users = (containers.data ?? []).filter((c) => c.image_id === i.id);
  // History entries that made a layer, in order: one per layer.
  const made = (oci.history ?? []).filter((h) => !h.empty_layer);
  const title = i.names[0] ? imageName(i.names[0]) : shortId(i.id);

  const remove = async () => {
    const ok = await ask({
      title: `Remove ${title}?`,
      body: users.length
        ? `${users.map((u) => u.name).join(", ")} still use it; its layers stay until they're gone.`
        : "Its names, and the blobs and snapshots nothing else uses.",
      confirm: "Remove",
      destructive: true,
    });
    if (!ok) return;
    let removed = true;
    for (const n of i.names.length ? i.names : [i.id]) {
      removed &&= await attempt(`Removing ${n} failed`, () => api.images.remove(n, users.length > 0));
    }
    if (removed) navigate("/images");
  };

  return (
    <div>
      {dialog}
      <PageHeader
        title={
          <span className="flex items-center gap-3">
            <Link to="/images" className="text-muted-foreground hover:text-foreground" aria-label="Back">
              <ArrowLeft className="size-5" />
            </Link>
            {title}
            {!i.unpacked && <Badge tone="warning">not unpacked yet</Badge>}
          </span>
        }
        subtitle={
          <span className="flex items-center gap-2">
            <Mono>{i.id}</Mono> <CopyButton text={i.id} />
          </span>
        }
        actions={
          <>
            <Button variant="primary" onClick={() => setRunning(true)}>
              <Play /> Run
            </Button>
            <Button onClick={() => void remove()}>
              <Trash2 /> Remove
            </Button>
          </>
        }
      />
      <div className="grid grid-cols-1 gap-4 p-6 xl:grid-cols-2">
        <Card>
          <CardHeader title="Image" />
          <CardContent>
            <Facts
              rows={[
                ["Names", <span key="n" className="flex flex-col">{i.names.map((n) => <Mono key={n}>{n}</Mono>)}</span>],
                ["Created", i.created ? ago(i.created, now) : "–"],
                ["Size", `${bytes(i.size)} compressed, ${i.layers} layer${i.layers === 1 ? "" : "s"}`],
                ["Platform", i.platform],
                ["Pulled as", i.repo_digest ? <Mono key="r" className="break-all">{i.repo_digest}</Mono> : "imported"],
                [
                  "Containers",
                  users.length ? (
                    <span key="c" className="flex flex-wrap gap-1.5">
                      {users.map((u) => (
                        <Link key={u.id} to={`/containers/${u.id}`} className="text-primary hover:underline">
                          {u.name}
                        </Link>
                      ))}
                    </span>
                  ) : (
                    "none"
                  ),
                ],
              ]}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader title="What it runs" description="From the image config; run options override it." />
          <CardContent>
            <Facts
              rows={[
                ["Entrypoint", cfg.Entrypoint?.length ? <Mono key="e">{commandText(cfg.Entrypoint)}</Mono> : "–"],
                ["Command", cfg.Cmd?.length ? <Mono key="c">{commandText(cfg.Cmd)}</Mono> : "–"],
                ["Working dir", cfg.WorkingDir || "/"],
                ["User", cfg.User || "root"],
                ["Ports", Object.keys(cfg.ExposedPorts ?? {}).join(", ") || "–"],
                ["Volumes", Object.keys(cfg.Volumes ?? {}).join(", ") || "–"],
                ["Stop signal", cfg.StopSignal ?? "SIGTERM"],
                [
                  "Environment",
                  <span key="env" className="flex flex-col">
                    {(cfg.Env ?? []).map((e) => (
                      <Mono key={e} className="break-all">
                        {e}
                      </Mono>
                    ))}
                  </span>,
                ],
              ]}
            />
          </CardContent>
        </Card>
        <Card className="xl:col-span-2">
          <CardHeader
            title="Layers"
            description="Bottom first. Each is a compressed tar blob, unpacked once into a snapshot named by its chain ID; a container's root is these, stacked by overlayfs."
          />
          <CardContent className="p-0">
            <Table data-testid="layers">
              <thead>
                <tr>
                  <Th className="pl-4">#</Th>
                  <Th>Blob</Th>
                  <Th>Size</Th>
                  <Th>Snapshot (chain ID)</Th>
                  <Th>Made by</Th>
                </tr>
              </thead>
              <tbody>
                {i.layer_details.map((l, n) => (
                  <Tr key={l.digest + n}>
                    <Td className="pl-4 tabular-nums">{n + 1}</Td>
                    <Td>
                      <Mono title={l.digest}>{shortId(l.digest)}</Mono>
                    </Td>
                    <Td className="tabular-nums">{bytes(l.size)}</Td>
                    <Td>
                      <Mono title={l.chain_id}>{shortId(l.chain_id)}</Mono>
                      {l.unpacked ? <Badge tone="success" className="ml-2">unpacked</Badge> : <Badge className="ml-2">packed</Badge>}
                    </Td>
                    <Td className="max-w-md">
                      <Mono className="text-muted-foreground block truncate" title={made[n]?.created_by}>
                        {made[n]?.created_by?.replace(/^\/bin\/sh -c (#\(nop\) )?/, "") ?? "–"}
                      </Mono>
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </CardContent>
        </Card>
        <Card className="xl:col-span-2">
          <CardHeader title="Config" description="The image config as stored." />
          <CardContent>
            <JsonView value={i.config} />
          </CardContent>
        </Card>
      </div>
      {running && <RunDialog open onOpenChange={(o) => !o && setRunning(false)} image={i.names[0] ? imageName(i.names[0]) : i.id} />}
    </div>
  );
}
