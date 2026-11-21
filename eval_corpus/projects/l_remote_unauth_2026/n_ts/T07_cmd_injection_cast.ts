import { execFile } from "child_process";
import path from "path";
import type { Request, Response } from "express";

export function convert(req: Request, res: Response) {
  const file = path.basename(String(req.query.file));
  execFile("convert", [file, "out.png"], (err, stdout) => res.send(stdout));
}
