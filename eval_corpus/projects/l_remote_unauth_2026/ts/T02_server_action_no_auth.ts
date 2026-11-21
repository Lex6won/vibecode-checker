"use server";

import { prisma } from "@/lib/prisma";

export async function deleteUser(userId: string) {
  await prisma.user.delete({ where: { id: userId } });
}

export async function updateRole(userId: string, role: string) {
  await prisma.user.update({ where: { id: userId }, data: { role } });
}
