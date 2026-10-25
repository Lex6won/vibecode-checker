import type { Request } from "express";
export function commandFrom(req: Request): string {
  return String(req.body.cmd);
}
