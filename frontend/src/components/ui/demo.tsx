import React, { useState } from "react";

import ClaudeStyleChatInput from "@/components/ui/claude-style-chat-input";

export default function ChatboxDemo() {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<string[]>([]);

  const currentHour = new Date().getHours();
  let greeting = "Good morning";
  if (currentHour >= 12 && currentHour < 18) greeting = "Good afternoon";
  if (currentHour >= 18) greeting = "Good evening";

  return (
    <div className="flex min-h-screen w-full flex-col items-center justify-center bg-bg-0 p-4 text-text-100">
      <div className="mb-8 w-full max-w-3xl text-center animate-fade-in">
        <div className="mx-auto mb-6 h-24 w-24 overflow-hidden rounded-full border border-bg-300 shadow-lg">
          <img
            src="https://images.unsplash.com/photo-1518773553398-650c184e0bb3?auto=format&fit=crop&w=300&q=80"
            alt="Decorative stock"
            className="h-full w-full object-cover"
          />
        </div>
        <h1 className="text-3xl font-light text-text-200 sm:text-4xl">
          {greeting}, <span className="text-accent">Security Team</span>
        </h1>
      </div>

      <div className="w-full max-w-3xl">
        <ClaudeStyleChatInput
          value={message}
          onChange={setMessage}
          onSendMessage={({ message: outgoing }) => {
            setMessages((prev) => [...prev, outgoing]);
            setMessage("");
          }}
          placeholder="Ask about findings, exploit paths, and fixes..."
        />
      </div>

      {messages.length ? (
        <div className="mt-6 w-full max-w-3xl rounded-2xl border border-bg-300 bg-bg-100 p-4">
          <p className="mb-3 text-xs uppercase tracking-wide text-text-400">Sent messages</p>
          <div className="space-y-2">
            {messages.map((entry, index) => (
              <p key={`${entry}-${index}`} className="rounded-lg bg-bg-200 px-3 py-2 text-sm text-text-100">
                {entry}
              </p>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
