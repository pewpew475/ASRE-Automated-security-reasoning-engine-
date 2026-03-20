import { X } from "lucide-react";

import { PoCViewer } from "@/components/findings/PoCViewer";
import { SeverityBadge } from "@/components/ui/SeverityBadge";
import { CodeBlock } from "@/components/ui/CodeBlock";
import type { Finding } from "@/types";

export function FindingDetail({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  if (!finding) {
    return null;
  }

  return (
    <aside className="fixed inset-y-0 right-0 z-40 w-full max-w-[600px] overflow-auto border-l border-bg-tertiary bg-bg-primary p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-lg font-semibold">{finding.title}</h3>
        <button type="button" onClick={onClose}><X className="h-5 w-5" /></button>
      </div>
      <div className="mb-3 flex items-center gap-2"><SeverityBadge severity={finding.severity} /><span>{finding.vuln_type}</span></div>
      <div className="grid grid-cols-2 gap-2 text-xs text-text-secondary">
        <div>URL: {finding.endpoint_url}</div>
        <div>Parameter: {finding.parameter || "N/A"}</div>
        <div>OWASP: {finding.owasp_category || "N/A"}</div>
        <div>MITRE: {finding.mitre_id || "N/A"}</div>
      </div>
      <section className="mt-4 space-y-2">
        <h4 className="font-semibold">Description</h4>
        <p className="text-sm text-text-secondary">{finding.description || "No description"}</p>
      </section>
      <section className="mt-4 rounded border-l-4 border-l-indigo-400 bg-indigo-900/20 p-3">
        <h4 className="font-semibold">LLM Impact Analysis</h4>
        <p className="text-sm italic text-text-secondary">{finding.llm_impact || "Analysis not available"}</p>
      </section>
      <section className="mt-4 space-y-2">
        <h4 className="font-semibold">Fix Suggestion</h4>
        <CodeBlock code={finding.fix_suggestion || "[]"} language="json" />
      </section>
      <section className="mt-4">
        <h4 className="mb-2 font-semibold">PoC Evidence</h4>
        <PoCViewer pocCurl={finding.poc_curl || "PoC not available"} pocFetch={finding.poc_fetch || "PoC not available"} pocNotes={finding.poc_notes || "Review response for behavior differences."} />
      </section>
    </aside>
  );
}
