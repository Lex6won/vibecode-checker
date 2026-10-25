"use client";
const ADMIN_PIN = process.env.NEXT_PUBLIC_ADMIN_PIN || "";
export default function Layout({ children }: { children: React.ReactNode }) {
  const ok = typeof window !== "undefined" && sessionStorage.getItem("admin_authenticated") === "true";
  return ok ? <>{children}</> : null;
}
