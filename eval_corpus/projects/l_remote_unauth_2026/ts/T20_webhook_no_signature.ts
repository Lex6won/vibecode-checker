import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

export async function POST(request: Request) {
  const event = await request.json();
  if (event.type === "payment.succeeded") {
    await prisma.order.update({ where: { id: event.orderId }, data: { paid: true } });
  }
  return NextResponse.json({ received: true });
}
