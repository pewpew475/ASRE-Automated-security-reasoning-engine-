import { useMemo, useState } from "react";

import { CodeBlock } from "@/components/ui/CodeBlock";

interface PoCViewerProps {
  pocCurl: string;
  pocFetch: string;
  pocNotes: string;
}

export function PoCViewer({ pocCurl, pocFetch, pocNotes }: PoCViewerProps) {
  const [tab, setTab] = useState<"curl" | "js">("curl");
  const jsLanguage = useMemo(() => (pocFetch.trim().startsWith("<!DOCTYPE html>") ? "html" : "javascript"), [pocFetch]);

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        <button type="button" onClick={() => setTab("curl")} className={`rounded px-2 py-1 text-xs ${tab === "curl" ? "bg-brand text-bg-primary" : "bg-bg-tertiary"}`}>
          curl
        </button>
        <button type="button" onClick={() => setTab("js")} className={`rounded px-2 py-1 text-xs ${tab === "js" ? "bg-brand text-bg-primary" : "bg-bg-tertiary"}`}>
          JavaScript
        </button>
      </div>
      {tab === "curl" ? <CodeBlock code={pocCurl} language="bash" filename="poc.sh" /> : <CodeBlock code={pocFetch} language={jsLanguage} filename="poc.js" />}
      <div className="rounded border border-yellow-500/40 bg-yellow-900/20 p-2 text-xs text-yellow-100">
        Run only on authorized targets. {pocNotes}
      </div>
    </div>
  );
}
