import { Bot, Loader2, Send, ShieldCheck, Sparkles, User } from "lucide-react";
import { useMemo, useState } from "react";
import toast from "react-hot-toast";

import { reportsApi } from "@/api/reports";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

const starterPrompts = [
  "Prioritize the top 5 fixes by risk reduction and effort.",
  "Explain the most exploitable attack path and how to break it.",
  "Give patch verification steps for critical and high findings.",
  "Create a remediation rollout plan for engineering and QA.",
];

export function ReportAssistantPanel({ scanId }: { scanId: string }) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      role: "assistant",
      content:
        "I can answer questions about this report, prioritize fixes, and provide implementation guidance based on the scan findings and chains.",
    },
  ]);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);

  const canSend = useMemo(() => question.trim().length >= 3 && !busy, [busy, question]);

  const sendQuestion = async (input: string) => {
    const trimmed = input.trim();
    if (trimmed.length < 3 || busy) {
      return;
    }

    const outgoing: ChatMessage = { role: "user", content: trimmed };
    const next = [...messages, outgoing];
    setMessages(next);
    setQuestion("");
    setBusy(true);

    try {
      const response = await reportsApi.askAssistant(scanId, {
        question: trimmed,
        history: next.slice(-12),
      });

      const answer = (response.data.answer || "").trim() || "No answer generated from report context.";
      setMessages((prev) => [...prev, { role: "assistant", content: answer }]);
    } catch (error: any) {
      const detail = error?.response?.data?.detail || "Report assistant failed";
      toast.error(String(detail));
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "I could not answer this right now. Confirm the backend and worker are running, and that report context exists for this scan.",
        },
      ]);
    } finally {
      setBusy(false);
    }
  };

  return (
    <aside className="flex h-full min-h-[calc(100vh-12rem)] flex-col rounded-2xl border border-bg-tertiary bg-gradient-to-b from-bg-secondary/95 via-bg-secondary/90 to-bg-primary/95 p-4 shadow-2xl shadow-black/30 backdrop-blur">
      <div className="mb-3 flex items-start justify-between gap-2 border-b border-bg-tertiary pb-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-text-primary">
            <Sparkles className="h-4 w-4 text-brand" />
            Report AI Assistant
          </h3>
          <p className="mt-1 text-xs text-text-secondary">Grounded on this report, findings, and chain data from your scan.</p>
        </div>
        <div className="rounded-full border border-emerald-400/40 bg-emerald-500/10 px-2 py-1 text-[10px] font-semibold text-emerald-300">
          LLM: env model
        </div>
      </div>

      <div className="mb-3 flex flex-wrap gap-2">
        {starterPrompts.map((prompt) => (
          <button
            key={prompt}
            type="button"
            onClick={() => void sendQuestion(prompt)}
            className="rounded-full border border-bg-tertiary bg-bg-primary/80 px-3 py-1 text-xs text-text-secondary transition hover:-translate-y-0.5 hover:border-brand hover:text-text-primary"
            disabled={busy}
          >
            {prompt}
          </button>
        ))}
      </div>

      <div className="flex-1 space-y-3 overflow-auto rounded-xl border border-bg-tertiary bg-bg-primary/60 p-3">
        {messages.map((message, index) => (
          <div
            key={`${message.role}-${index}`}
            className={`rounded-lg p-2 text-xs leading-5 ${
              message.role === "assistant"
                ? "border border-brand/35 bg-gradient-to-r from-brand/10 to-cyan-400/5 text-text-primary"
                : "border border-bg-tertiary bg-bg-secondary/95 text-text-secondary"
            }`}
          >
            <div className="mb-1 flex items-center gap-2 font-semibold uppercase tracking-wide opacity-90">
              {message.role === "assistant" ? <Bot className="h-3.5 w-3.5 text-brand" /> : <User className="h-3.5 w-3.5 text-text-secondary" />}
              {message.role}
            </div>
            <MessageContent content={message.content} isAssistant={message.role === "assistant"} />
          </div>
        ))}
        {busy ? (
          <div className="inline-flex items-center gap-2 rounded-lg border border-brand/30 bg-brand/10 px-3 py-2 text-xs text-text-secondary">
            <Loader2 className="h-3 w-3 animate-spin" />
            Analyzing report context...
          </div>
        ) : null}
      </div>

      <form
        className="mt-3 flex items-end gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          void sendQuestion(question);
        }}
      >
        <div className="flex-1">
          <label className="mb-1 inline-flex items-center gap-1 text-[11px] uppercase tracking-wide text-text-secondary">
            <ShieldCheck className="h-3 w-3" />
            Ask about risk, exploitability, or remediation
          </label>
          <input
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder="Example: Which controls should be patched first to reduce blast radius?"
          className="w-full rounded-md border border-bg-tertiary bg-bg-primary px-3 py-2 text-xs outline-none ring-brand/40 placeholder:text-text-secondary focus:ring"
          />
        </div>
        <button
          type="submit"
          disabled={!canSend}
          className="inline-flex items-center gap-1 rounded-md bg-brand px-3 py-2 text-xs font-semibold text-bg-primary transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Send className="h-3 w-3" />
          Send
        </button>
      </form>
    </aside>
  );
}

function MessageContent({ content, isAssistant }: { content: string; isAssistant: boolean }) {
  if (!isAssistant) {
    return <div className="whitespace-pre-wrap">{content}</div>;
  }

  const lines = content
    .split("\n")
    .map((line) => line.trimEnd())
    .filter((line, index, all) => !(line.length === 0 && all[index - 1]?.length === 0));

  return (
    <div className="space-y-2">
      {lines.map((line, index) => {
        const trimmed = line.trim();
        if (/^\d+\./.test(trimmed)) {
          return (
            <div key={`line-${index}`} className="flex items-start gap-2">
              <span className="mt-0.5 rounded bg-brand/20 px-1.5 py-0.5 text-[10px] font-bold text-brand">
                {trimmed.match(/^\d+\./)?.[0].replace(".", "")}
              </span>
              <span className="whitespace-pre-wrap">{trimmed.replace(/^\d+\.\s*/, "")}</span>
            </div>
          );
        }

        if (/^[-*]\s+/.test(trimmed)) {
          return (
            <div key={`line-${index}`} className="flex items-start gap-2">
              <span className="mt-1 h-1.5 w-1.5 rounded-full bg-cyan-300" />
              <span className="whitespace-pre-wrap">{trimmed.replace(/^[-*]\s+/, "")}</span>
            </div>
          );
        }

        if (trimmed.endsWith(":")) {
          return (
            <h4 key={`line-${index}`} className="text-xs font-semibold uppercase tracking-wide text-cyan-200">
              {trimmed.slice(0, -1)}
            </h4>
          );
        }

        return (
          <p key={`line-${index}`} className="whitespace-pre-wrap text-xs leading-5 text-text-primary">
            {line}
          </p>
        );
      })}
    </div>
  );
}
