import { prisma } from "@/lib/prisma";

export async function findUser(name: string) {
  return prisma.$queryRaw`SELECT * FROM "User" WHERE name = ${name}`;
}
