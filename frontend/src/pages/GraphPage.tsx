import { ArrowLeft } from "lucide-react";
import { useParams, useNavigate } from "react-router-dom";

import { AttackGraph } from "@/components/graph/AttackGraph";

export function GraphPage() {
  const navigate = useNavigate();
  const { scanId = "" } = useParams();

  return (
    <div className="space-y-3">
      <button type="button" onClick={() => navigate(`/scans/${scanId}`)} className="rounded bg-bg-secondary px-3 py-1.5 text-sm text-text-secondary">
        <ArrowLeft className="mr-1 inline h-4 w-4" /> Back to Scan
      </button>
      <AttackGraph scanId={scanId} />
    </div>
  );
}
