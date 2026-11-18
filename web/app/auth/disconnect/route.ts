import { api } from "@/lib/api";

export async function POST(request: Request) {
  const host = request.headers.get("host") ?? "";
  await api("/api/llm/chatgpt/disconnect", {});
  return Response.redirect(`http://${host}/settings`, 303);
}
