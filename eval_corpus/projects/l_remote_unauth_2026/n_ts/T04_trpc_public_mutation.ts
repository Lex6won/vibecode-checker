import { z } from "zod";
import { adminProcedure, router } from "./trpc";
import { prisma } from "./prisma";

export const adminRouter = router({
  deleteUser: adminProcedure.input(z.object({ id: z.string() })).mutation(async ({ input }) => {
    return prisma.user.delete({ where: { id: input.id } });
  }),
});
