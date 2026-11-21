import { NextRequest, NextResponse } from "next/server";

const ALLOWED = new Set(["api.example.go.kr"]);

export async function GET(request: NextRequest) {
  const target = new URL(request.nextUrl.searchParams.get("url") ?? "");
  if (!ALLOWED.has(target.hostname)) return NextResponse.json({ error: "forbidden" }, { status: 403 });
  const upstream = await fetch("https://api.example.go.kr/status");
  return new NextResponse(await upstream.text());
}
