import { exec } from "child_process";
import type { Request, Response } from "express";

export function convert(req: Request, res: Response) {
  const file = req.query.file as string;
  exec(`convert ${file} out.png`, (err, stdout) => res.send(stdout));
}
