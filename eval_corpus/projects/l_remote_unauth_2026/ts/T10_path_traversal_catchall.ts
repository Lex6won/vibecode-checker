import fs from "fs";
import path from "path";

export async function GET(request: Request, { params }: { params: { slug: string[] } }) {
  const file = path.join(process.cwd(), "content", params.slug.join("/"));
  return new Response(fs.readFileSync(file, "utf8"));
}
