import type { Request, Response } from "express";

export function run(req: Request, res: Response) {
  const code = (req.body as any).code;
  res.json({ result: (eval as any)(code) });
}
