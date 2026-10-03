import { Loader2 } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/cn";

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("text-muted-foreground size-4 animate-spin", className)} />;
}

/** What a view shows when it has nothing to show. */
export function Empty({ icon, title, children, className }: { icon?: ReactNode; title: ReactNode; children?: ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center gap-2 px-6 py-14 text-center", className)}>
      {icon && <div className="text-muted-foreground/60 [&_svg]:size-10">{icon}</div>}
      <p className="font-medium">{title}</p>
      {children && <div className="text-muted-foreground max-w-md text-sm">{children}</div>}
    </div>
  );
}

/** A monospace value that can be selected and copied. */
export function Mono({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span className={cn("selectable font-mono text-[12.5px]", className)} title={title}>
      {children}
    </span>
  );
}

/** Label/value rows. */
export function Facts({ rows, className }: { rows: [ReactNode, ReactNode][]; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm", className)}>
      {rows.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/** A thin bar for usage against a limit. */
export function Meter({ value, max, tone = "primary" }: { value: number; max: number | null; tone?: "primary" | "warning" | "destructive" }) {
  const share = max ? Math.min(1, value / max) : 0;
  const base = { primary: "bg-primary", warning: "bg-warning", destructive: "bg-destructive" }[tone];
  const color = share > 0.9 ? "bg-destructive" : share > 0.75 ? "bg-warning" : base;
  return (
    <div className="bg-muted h-1.5 w-full overflow-hidden rounded-full">
      <div className={cn("h-full rounded-full transition-[width]", max ? color : "bg-muted-foreground/30")} style={{ width: max ? `${share * 100}%` : "100%" }} />
    </div>
  );
}
