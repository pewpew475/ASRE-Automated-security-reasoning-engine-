interface ConfirmModalProps {
  open: boolean;
  title: string;
  description: string;
  onConfirm: () => void;
  onCancel: () => void;
  danger?: boolean;
}

export function ConfirmModal({ open, title, description, onConfirm, onCancel, danger = false }: ConfirmModalProps) {
  if (!open) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-md rounded-lg border border-bg-tertiary bg-bg-secondary p-5">
        <h3 className="text-lg font-semibold">{title}</h3>
        <p className="mt-2 text-sm text-text-secondary">{description}</p>
        <div className="mt-4 flex justify-end gap-2">
          <button type="button" className="rounded-md border border-bg-tertiary px-3 py-1.5" onClick={onCancel}>
            Cancel
          </button>
          <button
            type="button"
            className={`rounded-md px-3 py-1.5 font-medium ${danger ? "bg-red-600 text-white" : "bg-brand text-bg-primary"}`}
            onClick={onConfirm}
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}
