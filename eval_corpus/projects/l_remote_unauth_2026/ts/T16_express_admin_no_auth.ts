import express, { Request, Response } from "express";

const router = express.Router();

router.post("/admin/config", async (req: Request, res: Response) => {
  await saveConfig(req.body);
  res.json({ ok: true });
});

router.delete("/admin/users/:id", async (req: Request, res: Response) => {
  await removeUser(req.params.id);
  res.status(204).end();
});

export default router;
