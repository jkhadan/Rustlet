import { JsonView } from "@/components/JsonView";

/** What `rustlet inspect` prints, as the daemon sends it. */
export function InspectTab({ value }: { value: unknown }) {
  return (
    <div className="p-6">
      <JsonView value={value} />
    </div>
  );
}
