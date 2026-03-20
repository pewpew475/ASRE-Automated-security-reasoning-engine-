import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { atomDark } from "react-syntax-highlighter/dist/esm/styles/prism";

interface CodeBlockProps {
  code: string;
  language?: string;
  filename?: string;
}

export function CodeBlock({ code, language = "bash", filename }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  return (
    <div className="overflow-hidden rounded-lg border border-bg-tertiary bg-bg-secondary">
      <div className="flex items-center justify-between border-b border-bg-tertiary px-3 py-2 text-xs text-text-secondary">
        <span>{filename || language}</span>
        <button type="button" onClick={onCopy} className="inline-flex items-center gap-1 rounded px-2 py-1 hover:bg-bg-tertiary">
          {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <div className="max-h-96 overflow-auto">
        <SyntaxHighlighter style={atomDark} language={language} customStyle={{ margin: 0 }}>
          {code}
        </SyntaxHighlighter>
      </div>
    </div>
  );
}
