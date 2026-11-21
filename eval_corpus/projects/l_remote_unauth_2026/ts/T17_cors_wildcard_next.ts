import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const res = NextResponse.json(await loadPrivateData());
  res.headers.set("Access-Control-Allow-Origin", request.headers.get("origin") ?? "*");
  res.headers.set("Access-Control-Allow-Credentials", "true");
  return res;
}
