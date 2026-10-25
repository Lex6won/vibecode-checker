import { Router, Request, Response } from "express";
import { requireAdmin } from "./auth";
export const admin = Router();

admin.delete("/admin/users/:id", requireAdmin, async (req: Request, res: Response) => {
  res.sendStatus(204);
});
