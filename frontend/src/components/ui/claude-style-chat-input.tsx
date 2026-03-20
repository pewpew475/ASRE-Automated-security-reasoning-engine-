import { ArrowUp, Check, ChevronDown, Clock3, Loader2, Sparkles } from "lucide-react";
import React, { useEffect, useMemo, useRef, useState } from "react";

type Model = {
  id: string;
  name: string;
  description: string;
};

type SendPayload = {
  message: string;
  model: string;
  isThinkingEnabled: boolean;
};

type ClaudeStyleChatInputProps = {
  value: string;
  onChange: (value: string) => void;
  onSendMessage: (payload: SendPayload) => void;
  placeholder?: string;
  disabled?: boolean;
  busy?: boolean;
  models?: Model[];
  selectedModel?: string;
  onModelChange?: (modelId: string) => void;
};

const defaultModels: Model[] = [
  { id: "analysis", name: "Analysis", description: "Structured remediation and exploit chain analysis" },
  { id: "quick", name: "Quick", description: "Fast concise responses for triage" },
];

function ModelSelector({
  models,
  selectedModel,
  onSelect,
  disabled,
}: {
  models: Model[];
  selectedModel: string;
  onSelect: (modelId: string) => void;
  disabled?: boolean;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const currentModel = useMemo(() => models.find((m) => m.id === selectedModel) || models[0], [models, selectedModel]);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div ref={dropdownRef} className="relative">
      <button
        type="button"
        disabled={disabled}
        onClick={() => setIsOpen((prev) => !prev)}
        className="inline-flex h-8 items-center gap-1 rounded-xl px-2.5 text-xs font-medium text-text-300 transition hover:bg-bg-200 hover:text-text-200 disabled:cursor-not-allowed disabled:opacity-60"
      >
        <span className="whitespace-nowrap">{currentModel.name}</span>
        <ChevronDown className={`h-4 w-4 transition-transform ${isOpen ? "rotate-180" : ""}`} />
      </button>

      {isOpen ? (
        <div className="absolute bottom-full right-0 z-50 mb-2 w-64 overflow-hidden rounded-2xl border border-[#d6d6d6] bg-[#ffffff] p-1.5 shadow-2xl dark:border-[#454540] dark:bg-[#262624]">
          {models.map((model) => (
            <button
              key={model.id}
              type="button"
              onClick={() => {
                onSelect(model.id);
                setIsOpen(false);
              }}
              className="flex w-full items-start justify-between rounded-xl px-3 py-2.5 text-left transition hover:bg-bg-200"
            >
              <span className="flex flex-col gap-0.5">
                <span className="text-[13px] font-semibold text-text-100">{model.name}</span>
                <span className="text-[11px] text-text-300">{model.description}</span>
              </span>
              {selectedModel === model.id ? <Check className="mt-1 h-4 w-4 text-accent" /> : null}
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

export default function ClaudeStyleChatInput({
  value,
  onChange,
  onSendMessage,
  placeholder = "How can I help you with this report?",
  disabled,
  busy,
  models,
  selectedModel,
  onModelChange,
}: ClaudeStyleChatInputProps) {
  const [localModel, setLocalModel] = useState("analysis");
  const [isThinkingEnabled, setIsThinkingEnabled] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const effectiveModels = models?.length ? models : defaultModels;
  const effectiveSelectedModel = selectedModel || localModel;

  const canSend = value.trim().length >= 3 && !disabled && !busy;

  useEffect(() => {
    if (!textareaRef.current) return;
    textareaRef.current.style.height = "auto";
    textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 240)}px`;
  }, [value]);

  const updateModel = (nextModelId: string) => {
    if (onModelChange) {
      onModelChange(nextModelId);
      return;
    }
    setLocalModel(nextModelId);
  };

  const handleSend = () => {
    if (!canSend) return;
    onSendMessage({
      message: value.trim(),
      model: effectiveSelectedModel,
      isThinkingEnabled,
    });
  };

  return (
    <div className="w-full rounded-2xl border border-bg-tertiary/80 bg-white/5 p-3 shadow-lg shadow-black/20 transition focus-within:shadow-lg focus-within:shadow-black/30">
      <div className="relative mb-2">
        <textarea
          ref={textareaRef}
          rows={1}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              handleSend();
            }
          }}
          placeholder={placeholder}
          disabled={disabled || busy}
          className="max-h-60 min-h-12 w-full resize-none bg-transparent px-1 py-1 text-sm text-text-100 outline-none placeholder:text-text-400 disabled:cursor-not-allowed"
        />
      </div>

      <div className="flex items-center gap-2">
        <div className="flex flex-1 items-center gap-1">
          <button
            type="button"
            onClick={() => setIsThinkingEnabled((prev) => !prev)}
            className={`inline-flex h-8 w-8 items-center justify-center rounded-lg transition ${
              isThinkingEnabled ? "bg-accent/10 text-accent" : "text-text-400 hover:bg-bg-200 hover:text-text-200"
            }`}
            aria-pressed={isThinkingEnabled}
            disabled={disabled || busy}
            title="Extended reasoning"
          >
            <Sparkles className="h-4 w-4" />
          </button>

          <div className="inline-flex items-center gap-1 rounded-full border border-bg-300 bg-bg-200/60 px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-text-300">
            <Clock3 className="h-3 w-3" />
            {isThinkingEnabled ? "extended" : "standard"}
          </div>
        </div>

        <ModelSelector
          models={effectiveModels}
          selectedModel={effectiveSelectedModel}
          onSelect={updateModel}
          disabled={disabled || busy}
        />

        <button
          type="button"
          onClick={handleSend}
          disabled={!canSend}
          className="inline-flex h-8 w-8 items-center justify-center rounded-xl bg-accent text-bg-0 transition hover:bg-accent-hover disabled:cursor-not-allowed disabled:opacity-50"
          aria-label="Send message"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowUp className="h-4 w-4" />}
        </button>
      </div>
    </div>
  );
}