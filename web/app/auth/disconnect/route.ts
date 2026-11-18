import { isAdmin } from "@/lib/admin";
import { api } from "@/lib/api";

export async function POST(request: Request) {
  if (!(await isAdmin())) return new Response("Not found", { status: 404 });
  const host = request.headers.get("host") ?? "";
  await api("/api/llm/chatgpt/disconnect", {});
  return Response.redirect(`http://${host}/settings`, 303);
}
