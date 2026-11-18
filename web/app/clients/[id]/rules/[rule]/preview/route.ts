import { api } from "@/lib/api";

// Forwards a tuning preview to praxis-api, keeping the API token on the server.
export async function POST(request: Request, { params }: { params: Promise<{ id: string; rule: string }> }) {
  const { id, rule } = await params;
  try {
    const result = await api<object>(
      `/api/clients/${encodeURIComponent(id)}/rules/${encodeURIComponent(rule)}/preview`,
      await request.json(),
    );
    return Response.json(result ?? { error: "This client does not run that rule." }, { status: result ? 200 : 404 });
  } catch (error) {
    return Response.json({ error: String(error) }, { status: 502 });
  }
}
