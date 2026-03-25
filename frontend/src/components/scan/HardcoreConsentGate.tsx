import { useEffect, useState } from "react";
import toast from "react-hot-toast";

import apiClient from "@/api/client";

interface HardcoreConsentGateProps {
  domain: string;
  onLocked: (locked: boolean) => void;
}

export function HardcoreConsentGate({ domain, onLocked }: HardcoreConsentGateProps) {
  const [agreed, setAgreed] = useState(false);
  const [scopeLocked, setScopeLocked] = useState(false);

  useEffect(() => {
    if (!domain || domain === "your-domain.com") {
      setScopeLocked(false);
      setAgreed(false);
      onLocked(false);
    }
  }, [domain, onLocked]);

  const giveConsent = async () => {
    if (!domain || domain === "your-domain.com") {
      toast.error("Set a valid target URL first");
      return;
    }

    try {
      const { data } = await apiClient.post("/consent/init", {
        target_url: `https://${domain}`,
        agreed_to_tc: true,
      });
      if (!data?.consent_id) {
        throw new Error("Consent initialization failed");
      }
      setScopeLocked(true);
      onLocked(true);
      toast.success("Consent granted. You can continue with Hardcore mode.");
    } catch {
      toast.error("Unable to grant consent. Please try again.");
    }
  };

  return (
    <div className="rounded-lg border border-red-500/40 bg-red-950/20 p-4">
      <h3 className="mb-2 text-sm font-semibold">Hardcore Consent</h3>
      <p className="mb-2 text-xs text-text-secondary">
        Hardcore mode needs explicit consent acknowledgment before running active checks.
      </p>

      <label className="mt-2 flex items-center gap-2 text-xs">
        <input type="checkbox" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
        I understand and authorize active security testing for this target.
      </label>

      {!scopeLocked ? (
        <button
          type="button"
          className="mt-3 rounded bg-brand px-3 py-1.5 text-sm text-bg-primary disabled:opacity-50"
          disabled={!agreed}
          onClick={giveConsent}
        >
          Give Consent and Continue
        </button>
      ) : (
        <div className="mt-3 rounded border border-green-500/40 bg-green-500/10 px-3 py-2 text-xs text-green-300">
          Consent granted. Hardcore mode is ready.
        </div>
      )}
    </div>
  );
}
