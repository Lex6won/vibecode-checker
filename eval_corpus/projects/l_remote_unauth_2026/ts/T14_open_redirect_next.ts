import { redirect } from "next/navigation";

export default function Page({ searchParams }: { searchParams: { next?: string } }) {
  redirect(searchParams.next ?? "/");
}
