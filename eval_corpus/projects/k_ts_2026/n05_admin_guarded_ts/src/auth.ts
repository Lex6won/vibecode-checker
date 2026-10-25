import type { Request, Response, NextFunction } from "express";
export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.session?.isAdmin) return res.status(403).end();
  next();
}
