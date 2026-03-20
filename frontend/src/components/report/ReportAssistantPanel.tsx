import { Archive, Bot, Clock3, Loader2, MessageSquarePlus, Sparkles, User } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import toast from "react-hot-toast";

import { reportsApi } from "@/api/reports";
import ClaudeStyleChatInput from "@/components/ui/claude-style-chat-input";

type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  createdAt: string;
};

type ChatSession = {
  id: string;
  title: string;
  messages: ChatMessage[];
  createdAt: string;
  updatedAt: string;
};

const starterPrompts = [
  "Prioritize the top 5 fixes by risk reduction and effort.",
  "Explain the most exploitable attack path and how to break it.",
  "Give patch verification steps for critical and high findings.",
  "Create a remediation rollout plan for engineering and QA.",
];

const STORAGE_KEY = "asre-report-chat-v1";

const isoNow = () => new Date().toISOString();
const makeId = () => `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

const makeAssistantMessage = (content: string): ChatMessage => ({
  id: makeId(),
  role: "assistant",
  content,
  createdAt: isoNow(),
});

const makeUserMessage = (content: string): ChatMessage => ({
  id: makeId(),
  role: "user",
  content,
  createdAt: isoNow(),
});

const defaultAssistantText =
  "ASRE AI is ready. Ask about exploitability, root cause, remediation steps, validation checks, or rollout sequencing.";

const createSession = (): ChatSession => ({
  id: makeId(),
  title: "New chat",
  messages: [makeAssistantMessage(defaultAssistantText)],
  createdAt: isoNow(),
  updatedAt: isoNow(),
});

function loadScanSessions(scanId: string): ChatSession[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as Record<string, ChatSession[]>;
    return Array.isArray(parsed?.[scanId]) ? parsed[scanId] : [];
  } catch {
    return [];
  }
}

function saveScanSessions(scanId: string, sessions: ChatSession[]) {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const parsed = raw ? (JSON.parse(raw) as Record<string, ChatSession[]>) : {};
    parsed[scanId] = sessions;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
  } catch {
    // Ignore storage failures in restricted browser contexts.
  }
}

function buildSessionTitle(messages: ChatMessage[]) {
  const firstUser = messages.find((message) => message.role === "user")?.content.trim() || "New chat";
  return firstUser.length > 56 ? `${firstUser.slice(0, 56)}...` : firstUser;
}

export function ReportAssistantPanel({ scanId }: { scanId: string }) {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState("");
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const loaded = loadScanSessions(scanId);
    if (loaded.length) {
      const ordered = [...loaded].sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));
      setSessions(ordered);
      setActiveSessionId(ordered[0].id);
      return;
    }

    const initial = createSession();
    setSessions([initial]);
    setActiveSessionId(initial.id);
  }, [scanId]);

  useEffect(() => {
    if (!sessions.length) return;
    saveScanSessions(scanId, sessions);
  }, [scanId, sessions]);

  const activeSession = useMemo(
    () => sessions.find((session) => session.id === activeSessionId) || sessions[0] || null,
    [activeSessionId, sessions]
  );

  const messages = activeSession?.messages || [];
  const updateActiveSession = (updater: (session: ChatSession) => ChatSession) => {
    setSessions((prev) => {
      const base = prev.length ? prev : [createSession()];
      const targetId = activeSessionId || base[0].id;
      const next = base.map((session) => {
        if (session.id !== targetId) return session;
        const updated = updater(session);
        return {
          ...updated,
          title: buildSessionTitle(updated.messages),
          updatedAt: isoNow(),
        };
      });
      return [...next].sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : -1));
    });
  };

  const handleNewChat = () => {
    const next = createSession();
    setSessions((prev) => [next, ...prev]);
    setActiveSessionId(next.id);
    setQuestion("");
  };

  const sendQuestion = async (input: string) => {
    const trimmed = input.trim();
    if (trimmed.length < 3 || busy || !activeSession) {
      return;
    }

    const outgoing = makeUserMessage(trimmed);
    const provisional = [...messages, outgoing];
    updateActiveSession((session) => ({ ...session, messages: provisional }));
    setQuestion("");
    setBusy(true);

    try {
      const response = await reportsApi.askAssistant(scanId, {
        question: trimmed,
        history: provisional.slice(-12).map((message) => ({ role: message.role, content: message.content })),
      });

      const answer = (response.data.answer || "").trim() || "No answer generated from report context.";
      updateActiveSession((session) => ({
        ...session,
        messages: [...session.messages, makeAssistantMessage(answer)],
      }));
    } catch (error: any) {
      const detail = error?.response?.data?.detail || "Report assistant failed";
      toast.error(String(detail));
      updateActiveSession((session) => ({
        ...session,
        messages: [
          ...session.messages,
          makeAssistantMessage(
            "I could not answer right now. Check backend connectivity and confirm report context exists for this scan."
          ),
        ],
      }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <aside className="flex h-full min-h-[calc(100vh-12rem)] flex-col overflow-hidden rounded-2xl border border-bg-tertiary bg-gradient-to-b from-[#101f34] via-[#122741] to-[#0d1c33] p-3 shadow-2xl shadow-black/35 backdrop-blur">
      <div className="mb-2 flex items-center gap-2">
        <h3 className="mr-auto inline-flex items-center gap-2 text-sm font-semibold text-text-primary">
          <Sparkles className="h-4 w-4 text-cyan-300" />
          ASRE AI Chat
        </h3>
        <button
          type="button"
          onClick={handleNewChat}
          className="inline-flex items-center gap-1 rounded-lg bg-cyan-500/15 px-2.5 py-1.5 text-xs font-semibold text-cyan-200 transition hover:bg-cyan-500/25"
        >
          <MessageSquarePlus className="h-3.5 w-3.5" />
          New Chat
        </button>
      </div>

      <div className="mb-2 flex items-center gap-2">
        <div className="relative flex-1">
          <Clock3 className="pointer-events-none absolute left-2 top-2 h-3.5 w-3.5 text-text-secondary" />
          <select
            value={activeSession?.id || ""}
            onChange={(event) => setActiveSessionId(event.target.value)}
            className="w-full rounded-lg border border-bg-tertiary/80 bg-white/5 py-1.5 pl-7 pr-2 text-xs text-text-primary"
          >
            {sessions.map((session) => (
              <option key={session.id} value={session.id}>
                {session.title}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="mb-3 flex flex-wrap gap-2">
        {starterPrompts.map((prompt) => (
          <button
            key={prompt}
            type="button"
            onClick={() => void sendQuestion(prompt)}
            className="rounded-full bg-white/5 px-3 py-1 text-[11px] text-text-secondary transition hover:-translate-y-0.5 hover:bg-cyan-400/10 hover:text-text-primary"
            disabled={busy}
          >
            {prompt}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-auto px-1">
        <div className="space-y-2">
          {messages.map((message, index) => (
            <div
              key={message.id}
              className="animate-[fadeIn_220ms_ease-out] pb-2"
              style={{ animationDelay: `${Math.min(index * 20, 140)}ms` }}
            >
              <div className="w-full px-1 py-1 text-xs leading-5">
                <div className="mb-1 flex items-center gap-2 font-semibold uppercase tracking-wide opacity-90">
                  {message.role === "assistant" ? <Bot className="h-3.5 w-3.5 text-cyan-200" /> : <User className="h-3.5 w-3.5 text-cyan-200" />}
                  <span className={message.role === "assistant" ? "text-cyan-100" : "text-sky-200"}>{message.role}</span>
                  <span className="text-[10px] font-normal text-text-secondary">{new Date(message.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                </div>
                <MessageContent content={message.content} isAssistant={message.role === "assistant"} />
              </div>
            </div>
          ))}
          {busy ? (
            <div className="flex justify-start">
              <div className="inline-flex items-center gap-2 rounded-full bg-cyan-500/10 px-3 py-1.5 text-xs text-text-secondary">
                <Loader2 className="h-3 w-3 animate-spin" />
                ASRE AI is analyzing report context...
              </div>
            </div>
          ) : null}
          {!busy && !messages.length ? (
            <div className="rounded-xl border border-bg-tertiary bg-bg-primary/40 p-4 text-center text-xs text-text-secondary">
              <Archive className="mx-auto mb-2 h-4 w-4" />
              No messages yet. Start with a remediation or risk question.
            </div>
          ) : null}
        </div>
      </div>

      <div className="mt-2">
        <ClaudeStyleChatInput
          value={question}
          onChange={setQuestion}
          busy={busy}
          onSendMessage={({ message }) => {
            void sendQuestion(message);
          }}
          placeholder="Example: Which findings should we patch first to break the highest-risk attack chain?"
        />
      </div>
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
              <span className="mt-0.5 rounded bg-cyan-400/20 px-1.5 py-0.5 text-[10px] font-bold text-cyan-200">
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
