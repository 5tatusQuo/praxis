import { isAdmin } from "@/lib/admin";
import { api } from "@/lib/api";

// OpenAI sends the browser back here. The code is exchanged by praxis-api;
// no token ever reaches the browser.
export async function GET(request: Request) {
  if (!(await isAdmin())) return new Response("Not found", { status: 404 });
  const url = new URL(request.url);
  const host = request.headers.get("host") ?? url.host;
  const params = Object.fromEntries(url.searchParams.entries());
  let query = "connected=1";
  try {
    await api("/api/llm/chatgpt/callback", { params });
  } catch (error) {
    query = `error=${encodeURIComponent(String(error))}`;
  }
  return Response.redirect(`http://${host}/settings?${query}`, 303);
}
