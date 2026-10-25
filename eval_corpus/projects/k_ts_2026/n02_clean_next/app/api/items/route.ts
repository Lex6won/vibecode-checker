import { NextResponse } from "next/server";
import { z } from "zod";

const Body = z.object({ name: z.string().max(80) });

export async function POST(req: Request) {
  const body = Body.parse(await req.json());
  return NextResponse.json({ name: body.name });
}
