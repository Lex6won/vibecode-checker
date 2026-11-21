import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get("url") as string;
  const upstream = await fetch(target);
  return new NextResponse(await upstream.text());
}
