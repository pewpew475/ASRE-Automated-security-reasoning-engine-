import { useState } from "react";

export function GraphLegend() {
  const [open, setOpen] = useState(true);

  return (
    <div className="absolute right-4 top-4 z-10 w-56 rounded border border-bg-tertiary bg-bg-secondary p-3 text-xs">
      <button type="button" className="mb-2 w-full text-left font-semibold" onClick={() => setOpen((v) => !v)}>
        Graph Legend {open ? "-" : "+"}
      </button>
      {open ? (
        <div className="space-y-1 text-text-secondary">
          <Row color="bg-blue-500" label="Endpoint" />
          <Row color="bg-orange-500" label="Vulnerability" />
          <Row color="bg-green-500" label="Asset" />
          <Row color="bg-red-500" label="Impact" />
          <div className="pt-2 text-text-primary">Edges: dashed = relation flow</div>
        </div>
      ) : null}
    </div>
  );
}

function Row({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`h-2 w-2 rounded-full ${color}`} />
      <span>{label}</span>
    </div>
  );
}
