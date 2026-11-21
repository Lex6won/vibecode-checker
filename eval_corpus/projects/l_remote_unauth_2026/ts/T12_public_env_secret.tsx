"use client";

import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });

export async function ask(q: string) {
  return client.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: q }] });
}
