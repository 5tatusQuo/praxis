import { isAdmin } from "@/lib/admin";
import { api } from "@/lib/api";

// Starts Sign in with ChatGPT. The sign-in returns to a 127.0.0.1 address, so
// the callback is this dashboard's own /auth/callback on the port you are using.
export async function POST(request: Request) {
  if (!(await isAdmin())) return new Response("Not found", { status: 404 });
  const host = request.headers.get("host") ?? "";
  const back = (message: string) =>
    Response.redirect(`http://${host}/settings?error=${encodeURIComponent(message)}`, 303);
  if (!/^127\.0\.0\.1:\d+$/.test(host)) {
    return back("Open the dashboard as http://127.0.0.1:<port> to sign in with ChatGPT (not localhost).");
  }
  try {
    const started = await api<{ url: string }>("/api/llm/chatgpt/start", {
      redirect_uri: `http://${host}/auth/callback`,
    });
    return Response.redirect(started!.url, 303);
  } catch (error) {
    return back(String(error));
  }
}
