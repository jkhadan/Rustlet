import { Download, Layers, Play, Search, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router";

import type { ImageSummary } from "@/bindings";
import { attempt, ErrorState, PageHeader, useConfirm } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Empty, Mono, Spinner } from "@/components/ui/misc";
import { Table, Td, Th, Tr } from "@/components/ui/table";
import { Tooltip } from "@/components/ui/tooltip";
import { useNow } from "@/lib/daemon";
import { ago, bytes, imageName, shortId } from "@/lib/format";
import { api } from "@/lib/ipc";
import { useContainers, useImages } from "@/lib/queries";

import { RunDialog } from "../containers/RunDialog";
import { PullDialog } from "./PullDialog";

export function ImagesPage() {
  const images = useImages();
  const containers = useContainers(true);
  const [pulling, setPulling] = useState(false);
  const [running, setRunning] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [dialog, ask] = useConfirm();
  const now = useNow();
  const navigate = useNavigate();

  const users = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const c of containers.data ?? []) m.set(c.image_id, [...(m.get(c.image_id) ?? []), c.name]);
    return m;
  }, [containers.data]);

  const rows = (images.data ?? []).filter((i) => {
    const f = filter.trim().toLowerCase();
    return !f || i.id.includes(f) || i.names.some((n) => n.toLowerCase().includes(f));
  });
  const total = (images.data ?? []).reduce((n, i) => n + i.size, 0);

  const remove = async (image: ImageSummary) => {
    const name = image.names[0] ?? image.id;
    const used = users.get(image.id) ?? [];
    const ok = await ask({
      title: `Remove ${imageName(name)}?`,
      body: used.length
        ? `${used.join(", ")} still use${used.length === 1 ? "s" : ""} it. The name goes; its layers stay until no container needs them.`
        : "The name goes, and every blob and snapshot nothing else uses.",
      confirm: "Remove",
      destructive: true,
    });
    if (ok) await attempt(`Removing ${name} failed`, () => api.images.remove(name, used.length > 0));
  };

  return (
    <div>
      {dialog}
      <PageHeader
        title="Images"
        subtitle={images.data ? `${images.data.length} images · ${bytes(total)} compressed` : " "}
        actions={
          <Button variant="primary" onClick={() => setPulling(true)} data-testid="open-pull">
            <Download /> Pull
          </Button>
        }
      >
        <div className="relative mt-4 w-72">
          <Search className="text-muted-foreground pointer-events-none absolute top-2 left-2.5 size-4" />
          <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by name or id" className="pl-8" />
        </div>
      </PageHeader>
      <div className="px-6 py-4">
        {images.isPending ? (
          <div className="flex justify-center py-16">
            <Spinner />
          </div>
        ) : images.error ? (
          <ErrorState error={images.error} what="images" />
        ) : rows.length === 0 ? (
          <Empty icon={<Layers />} title={filter ? "No image matches" : "No images yet"}>
            {!filter && "Pull one, or run a container: its image is pulled on the way."}
          </Empty>
        ) : (
          <div className="bg-card overflow-hidden rounded-lg border">
            <Table data-testid="images-table">
              <thead>
                <tr>
                  <Th>Name</Th>
                  <Th>ID</Th>
                  <Th>Size</Th>
                  <Th>Layers</Th>
                  <Th>Created</Th>
                  <Th>Platform</Th>
                  <Th>Used by</Th>
                  <Th className="w-0" />
                </tr>
              </thead>
              <tbody>
                {rows.map((i) => {
                  const used = users.get(i.id) ?? [];
                  const name = i.names[0];
                  return (
                    <Tr key={i.id} className="cursor-pointer" onClick={() => navigate(`/images/${encodeURIComponent(name ?? i.id)}`)} data-testid="image-row" data-name={name}>
                      <Td>
                        <Link to={`/images/${encodeURIComponent(name ?? i.id)}`} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
                          {name ? imageName(name) : <span className="text-muted-foreground">&lt;none&gt;</span>}
                        </Link>
                        {i.names.length > 1 && (
                          <Tooltip content={i.names.slice(1).map(imageName).join(", ")}>
                            <Badge className="ml-2">+{i.names.length - 1}</Badge>
                          </Tooltip>
                        )}
                      </Td>
                      <Td>
                        <Mono className="text-muted-foreground">{shortId(i.id)}</Mono>
                      </Td>
                      <Td className="tabular-nums">{bytes(i.size)}</Td>
                      <Td className="tabular-nums">{i.layers}</Td>
                      <Td className="text-muted-foreground whitespace-nowrap">{i.created ? ago(i.created, now) : "–"}</Td>
                      <Td className="text-muted-foreground">{i.platform}</Td>
                      <Td>{used.length ? <Badge tone="info">{used.length} container{used.length === 1 ? "" : "s"}</Badge> : <span className="text-muted-foreground">–</span>}</Td>
                      <Td>
                        <div className="flex gap-1" onClick={(e) => e.stopPropagation()}>
                          <Tooltip content="Run a container">
                            <Button size="icon-sm" variant="ghost" onClick={() => setRunning(name ?? i.id)} aria-label="Run">
                              <Play />
                            </Button>
                          </Tooltip>
                          <Tooltip content="Remove">
                            <Button size="icon-sm" variant="ghost" onClick={() => void remove(i)} aria-label="Remove">
                              <Trash2 />
                            </Button>
                          </Tooltip>
                        </div>
                      </Td>
                    </Tr>
                  );
                })}
              </tbody>
            </Table>
          </div>
        )}
      </div>
      <PullDialog open={pulling} onOpenChange={setPulling} />
      {running && <RunDialog open onOpenChange={(o) => !o && setRunning(null)} image={imageName(running)} />}
    </div>
  );
}
