import { useEffect, useState } from "react";
import toast from "react-hot-toast";

import apiClient from "@/api/client";
import { CodeBlock } from "@/components/ui/CodeBlock";

interface HardcoreConsentGateProps {
  domain: string;
  onLocked: (locked: boolean) => void;
}

export function HardcoreConsentGate({ domain, onLocked }: HardcoreConsentGateProps) {
  const [step, setStep] = useState(1);
  const [agreed, setAgreed] = useState(false);
  const [verified, setVerified] = useState(false);
  const [scopeLocked, setScopeLocked] = useState(false);
  const [scopeConfirm, setScopeConfirm] = useState(false);
  const [consentId, setConsentId] = useState<string | null>(null);
  const [dnsValue, setDnsValue] = useState<string>("");

  useEffect(() => {
    if (!domain || domain === "your-domain.com") {
      setConsentId(null);
      setDnsValue("");
      setVerified(false);
      setScopeLocked(false);
      setScopeConfirm(false);
      setStep(1);
    }
  }, [domain]);

  const initConsent = async () => {
    if (!domain || domain === "your-domain.com") {
      toast.error("Set a valid target URL first");
      return;
    }

    try {
      const { data } = await apiClient.post("/consent/init", {
        target_url: `https://${domain}`,
        agreed_to_tc: true,
      });
      setConsentId(data.consent_id);
      setDnsValue(data.dns_txt_record || "");
      setStep(2);
    } catch {
      toast.error("Unable to initialize consent");
    }
  };

  const verify = async () => {
    if (!consentId) {
      toast.error("Initialize consent first");
      return;
    }

    try {
      await apiClient.post("/consent/verify-domain", { consent_id: consentId, domain });
      setVerified(true);
      setStep(3);
      toast.success("Domain verified");
    } catch {
      toast.error("DNS TXT record not found yet");
    }
  };

  const lockScope = async () => {
    if (!consentId) {
      toast.error("Initialize consent first");
      return;
    }

    try {
      await apiClient.post("/consent/lock-scope", { consent_id: consentId });
      setScopeLocked(true);
      onLocked(true);
      toast.success("Scope locked");
    } catch {
      toast.error("Unable to lock scope");
    }
  };

  return (
    <div className="rounded-lg border border-red-500/40 bg-red-950/20 p-4">
      <div className="mb-3 flex gap-2">
        {[1, 2, 3].map((s) => (
          <span key={s} className={`h-2 w-8 rounded-full ${step >= s ? "bg-red-400" : "bg-bg-tertiary"}`} />
        ))}
      </div>

      {step === 1 ? (
        <div>
          <h3 className="mb-2 text-sm font-semibold">Authorized Use Agreement</h3>
          <div className="max-h-32 overflow-auto rounded border border-bg-tertiary bg-bg-secondary p-2 text-xs text-text-secondary">
            By using Hardcore Mode you confirm authorized ownership, explicit permission, and bounded legal scope.
          </div>
          <label className="mt-3 flex items-center gap-2 text-xs">
            <input type="checkbox" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} />
            I have read and agree to the authorized use terms
          </label>
          <button
            type="button"
            className="mt-3 rounded bg-brand px-3 py-1.5 text-sm text-bg-primary disabled:opacity-50"
            disabled={!agreed}
            onClick={initConsent}
          >
            Continue
          </button>
        </div>
      ) : null}

      {step === 2 ? (
        <div>
          <h3 className="mb-2 text-sm font-semibold">Verify Domain Ownership</h3>
          <p className="mb-2 text-xs text-text-secondary">Add this TXT record for {domain}:</p>
          <CodeBlock code={dnsValue} language="text" filename="DNS TXT" />
          <button type="button" className="mt-3 rounded bg-brand px-3 py-1.5 text-sm text-bg-primary" onClick={verify}>
            Verify
          </button>
          <p className="mt-2 text-xs text-text-secondary">DNS propagation can take up to 5 minutes</p>
        </div>
      ) : null}

      {step === 3 ? (
        <div>
          <h3 className="mb-2 text-sm font-semibold">Lock Scan Scope</h3>
          <p className="text-xs text-text-secondary">Target domain: {domain}</p>
          <label className="mt-3 flex items-center gap-2 text-xs">
            <input type="checkbox" checked={scopeConfirm} onChange={(e) => setScopeConfirm(e.target.checked)} />
            I confirm the scan scope is limited to {domain}
          </label>
          <button
            type="button"
            className="mt-3 rounded bg-red-500 px-3 py-1.5 text-sm text-white disabled:opacity-50"
            disabled={!scopeConfirm || !verified || scopeLocked}
            onClick={lockScope}
          >
            Lock Scope & Continue
          </button>
        </div>
      ) : null}
    </div>
  );
}
