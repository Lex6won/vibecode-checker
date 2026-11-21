import { z } from "zod";
import { publicProcedure, router } from "./trpc";
import { prisma } from "./prisma";

export const adminRouter = router({
  deleteUser: publicProcedure.input(z.object({ id: z.string() })).mutation(async ({ input }) => {
    return prisma.user.delete({ where: { id: input.id } });
  }),
  listUsers: publicProcedure.query(() => prisma.user.findMany()),
});
