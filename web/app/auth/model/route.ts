import { api } from "@/lib/api";

export async function POST(request: Request) {
  const host = request.headers.get("host") ?? "";
  const form = await request.formData();
  await api("/api/llm/chatgpt/model", { model: String(form.get("model") ?? "") });
  return Response.redirect(`http://${host}/settings`, 303);
}
