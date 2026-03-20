import { Shield, Skull } from "lucide-react";

import { cn } from "@/utils";

interface ModeToggleProps {
  value: "normal" | "hardcore";
  onChange: (v: "normal" | "hardcore") => void;
}

export function ModeToggle({ value, onChange }: ModeToggleProps) {
  return (
    <div className="grid gap-3 md:grid-cols-2">
      <button
        type="button"
        className={cn(
          "rounded-lg border p-4 text-left",
          value === "normal" ? "border-brand bg-brand/10" : "border-bg-tertiary bg-bg-secondary"
        )}
        onClick={() => onChange("normal")}
      >
        <div className="mb-2 flex items-center gap-2">
          <Shield className="h-4 w-4 text-brand" />
          <strong>Normal Mode</strong>
        </div>
        <p className="text-xs text-text-secondary">Safe audit - no domain verification required</p>
        <ul className="mt-2 space-y-1 text-xs text-text-secondary">
          <li>✓ XSS, IDOR, CSRF detection</li>
          <li>✓ Attack chain builder</li>
          <li>✓ LLM impact analysis</li>
          <li>✓ PoC generator</li>
        </ul>
      </button>

      <button
        type="button"
        className={cn(
          "rounded-lg border p-4 text-left",
          value === "hardcore" ? "border-red-500 bg-red-900/20" : "border-bg-tertiary bg-bg-secondary"
        )}
        onClick={() => onChange("hardcore")}
      >
        <div className="mb-2 flex items-center gap-2">
          <Skull className="h-4 w-4 text-red-300" />
          <strong>Hardcore Mode</strong>
        </div>
        <p className="text-xs text-text-secondary">Active testing - DNS verification required</p>
        <ul className="mt-2 space-y-1 text-xs text-text-secondary">
          <li>✓ Everything in Normal</li>
          <li>✓ SQLMap SQL injection</li>
          <li>✓ Nuclei CVE templates</li>
          <li>✓ JWT and session checks</li>
        </ul>
        <p className="mt-2 text-xs text-red-300">Warning: Authorized targets only</p>
      </button>
    </div>
  );
}
