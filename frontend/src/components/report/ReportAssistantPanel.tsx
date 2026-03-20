import { Loader2, Send, Sparkles } from "lucide-react";
import { useMemo, useState } from "react";
import toast from "react-hot-toast";

import { reportsApi } from "@/api/reports";

type ChatMessage = {
  role: "user" | "assistant";
  content: string;
};

const starterPrompts = [
  "What should we fix first and why?",
  "Summarize business impact in plain language.",
  "Give a 7-day remediation plan.",
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
    <aside className="rounded-xl border border-bg-tertiary bg-bg-secondary/90 p-4 shadow-lg shadow-black/20 backdrop-blur">
      <div className="mb-3 flex items-start justify-between gap-2">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-text-primary">
            <Sparkles className="h-4 w-4 text-brand" />
            Report AI Assistant
          </h3>
          <p className="mt-1 text-xs text-text-secondary">Answers are grounded in this scan report and findings context.</p>
        </div>
      </div>

      <div className="mb-3 flex flex-wrap gap-2">
        {starterPrompts.map((prompt) => (
          <button
            key={prompt}
            type="button"
            onClick={() => void sendQuestion(prompt)}
            className="rounded-full border border-bg-tertiary bg-bg-primary px-3 py-1 text-xs text-text-secondary hover:border-brand hover:text-text-primary"
            disabled={busy}
          >
            {prompt}
          </button>
        ))}
      </div>

      <div className="max-h-[55vh] space-y-3 overflow-auto rounded-lg border border-bg-tertiary bg-bg-primary/70 p-3">
        {messages.map((message, index) => (
          <div
            key={`${message.role}-${index}`}
            className={`rounded-lg p-2 text-xs leading-5 ${
              message.role === "assistant"
                ? "border border-brand/30 bg-brand/10 text-text-primary"
                : "border border-bg-tertiary bg-bg-secondary text-text-secondary"
            }`}
          >
            <div className="mb-1 font-semibold uppercase tracking-wide opacity-80">{message.role}</div>
            <div className="whitespace-pre-wrap">{message.content}</div>
          </div>
        ))}
        {busy ? (
          <div className="inline-flex items-center gap-2 rounded-lg border border-bg-tertiary bg-bg-secondary px-3 py-2 text-xs text-text-secondary">
            <Loader2 className="h-3 w-3 animate-spin" />
            Thinking...
          </div>
        ) : null}
      </div>

      <form
        className="mt-3 flex items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          void sendQuestion(question);
        }}
      >
        <input
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          placeholder="Ask about findings, attack paths, or fixes"
          className="flex-1 rounded-md border border-bg-tertiary bg-bg-primary px-3 py-2 text-xs outline-none ring-brand/40 placeholder:text-text-secondary focus:ring"
        />
        <button
          type="submit"
          disabled={!canSend}
          className="inline-flex items-center gap-1 rounded-md bg-brand px-3 py-2 text-xs font-semibold text-bg-primary disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Send className="h-3 w-3" />
          Send
        </button>
      </form>
    </aside>
  );
}
