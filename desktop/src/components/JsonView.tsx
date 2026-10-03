import { useMemo } from "react";

import { CopyButton } from "./common";

// Strings (keys when a colon follows), numbers, true/false/null.
const TOKEN = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g;

/** JSON, indented and coloured, selectable, with a copy button. */
export function JsonView({ value }: { value: unknown }) {
  const text = useMemo(() => JSON.stringify(value, null, 2), [value]);
  const parts = useMemo(() => {
    const out: React.ReactNode[] = [];
    let at = 0;
    let i = 0;
    for (const m of text.matchAll(TOKEN)) {
      const start = m.index ?? 0;
      if (start > at) out.push(text.slice(at, start));
      const [whole, str, colon, word, num] = m;
      const cls = str ? (colon ? "text-sky-600 dark:text-sky-400" : "text-emerald-700 dark:text-emerald-400") : word ? "text-violet-600 dark:text-violet-400" : num ? "text-amber-700 dark:text-amber-400" : "";
      out.push(
        <span key={i++} className={cls}>
          {str ?? whole}
        </span>,
      );
      if (colon) out.push(colon);
      at = start + whole.length;
    }
    out.push(text.slice(at));
    return out;
  }, [text]);
  return (
    <div className="relative">
      <CopyButton text={text} className="bg-card absolute top-2 right-2 rounded-md border p-1.5" />
      <pre className="selectable bg-card overflow-x-auto rounded-lg border p-4 font-mono text-[12px] leading-relaxed">{parts}</pre>
    </div>
  );
}
