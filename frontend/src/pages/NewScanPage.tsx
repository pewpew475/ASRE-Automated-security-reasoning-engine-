import { ScanConfigForm } from "@/components/scan/ScanConfigForm";

export function NewScanPage() {
  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-semibold">New Scan</h1>
        <p className="text-sm text-text-secondary">Configure scan mode, target, and authentication context.</p>
      </div>
      <ScanConfigForm />
    </div>
  );
}
