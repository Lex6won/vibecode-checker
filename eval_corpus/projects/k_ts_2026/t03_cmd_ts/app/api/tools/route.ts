import { exec } from "child_process";

export async function POST(req: Request) {
  const body = await req.json();
  const cmd = body.cmd as string;
  exec(`convert ${cmd!}`, () => {});
  return Response.json({ ok: true });
}
