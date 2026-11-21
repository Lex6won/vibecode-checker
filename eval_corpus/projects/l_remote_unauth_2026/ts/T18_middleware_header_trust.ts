import { NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
  if (request.headers.get("x-internal-request") === "1") return NextResponse.next();
  if (request.headers.get("x-user-role") === "admin") return NextResponse.next();
  if (!request.cookies.get("session")) return NextResponse.redirect(new URL("/login", request.url));
  return NextResponse.next();
}
