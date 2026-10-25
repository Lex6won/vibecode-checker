import { Router, Request, Response } from "express";
export const admin = Router();

admin.delete("/admin/users/:id", async (req: Request, res: Response) => {
  await removeUser(req.params.id);
  res.sendStatus(204);
});

async function removeUser(id: string): Promise<void> {}
