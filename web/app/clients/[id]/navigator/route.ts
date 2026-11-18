import { canSee, currentSession } from "@/lib/session";
import { api } from "@/lib/api";

// Proxies the Navigator layer download so the API token stays on the server.
export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!canSee(await currentSession(), id)) return new Response("Not found", { status: 404 });
  const layer = await api<object>(`/api/clients/${encodeURIComponent(id)}/navigator`);
  if (!layer) return new Response("No snapshot for this client", { status: 404 });
  return new Response(JSON.stringify(layer), {
    headers: {
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="praxis-${id}-coverage-layer.json"`,
    },
  });
}
