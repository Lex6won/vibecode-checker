"use client";

import { useState } from "react";

export function Answer({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}

export function Chat() {
  const [answer, setAnswer] = useState("");
  async function ask(q: string) {
    const r = await fetch("/api/chat", { method: "POST", body: JSON.stringify({ q }) });
    setAnswer((await r.json()).content);
  }
  return <Answer html={answer} />;
}
