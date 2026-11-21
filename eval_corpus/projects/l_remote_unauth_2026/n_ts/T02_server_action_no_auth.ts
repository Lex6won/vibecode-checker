"use server";

import { auth } from "@/lib/auth";
import { prisma } from "@/lib/prisma";

export async function deleteUser(userId: string) {
  const session = await auth();
  if (session?.user?.role !== "admin") throw new Error("forbidden");
  await prisma.user.delete({ where: { id: userId } });
}
