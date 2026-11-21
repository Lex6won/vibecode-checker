import { prisma } from "@/lib/prisma";

export async function findUser(name: string) {
  return prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE name = '${name}'`);
}

export async function GET(request: Request) {
  const name = new URL(request.url).searchParams.get("name")!;
  return Response.json(await findUser(name));
}
