import { isAdmin } from "@/lib/admin";
import { api } from "@/lib/api";

export async function POST(request: Request) {
  if (!(await isAdmin())) return new Response("Not found", { status: 404 });
  const host = request.headers.get("host") ?? "";
  const form = await request.formData();
  await api("/api/llm/chatgpt/model", { model: String(form.get("model") ?? "") });
  return Response.redirect(`http://${host}/settings`, 303);
}
