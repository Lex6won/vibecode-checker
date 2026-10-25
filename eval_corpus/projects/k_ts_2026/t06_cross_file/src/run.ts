import { exec } from "child_process";
import type { Request, Response } from "express";
import { commandFrom } from "./input";

export function handler(req: Request, res: Response) {
  exec("tool " + commandFrom(req), () => res.sendStatus(204));
}
