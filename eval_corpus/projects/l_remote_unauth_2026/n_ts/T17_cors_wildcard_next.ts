import { NextResponse } from "next/server";

const ALLOWED = new Set(["https://portal.example.go.kr"]);

export async function GET(request: Request) {
  const res = NextResponse.json(await loadPublicNotices());
  const origin = request.headers.get("origin") ?? "";
  if (ALLOWED.has(origin)) res.headers.set("Access-Control-Allow-Origin", origin);
  return res;
}
