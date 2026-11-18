import { requireAdmin } from "@/lib/admin";
import { Panel } from "@/components/Stat";
import { api, type AuditRow, when } from "@/lib/api";

export const dynamic = "force-dynamic";

function brief(detail: Record<string, unknown>): string {
  const text = JSON.stringify(detail);
  return text.length > 220 ? `${text.slice(0, 220)}…` : text;
}

export default async function Audit() {
  await requireAdmin();
  const rows = (await api<AuditRow[]>("/api/audit?limit=300")) ?? [];
  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold">Audit</h1>
        <p className="text-sm text-mute">
          Every model call, tool call and guardrail decision made by an agent, newest first.
        </p>
      </div>
      <Panel title="Agent activity" note={`${rows.length} most recent events`}>
        {rows.length === 0 ? (
          <p className="text-sm text-mute">No agent has run yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-mute">
                <tr>
                  <th className="py-1 pr-3">When</th>
                  <th className="py-1 pr-3">Actor</th>
                  <th className="py-1 pr-3">Client</th>
                  <th className="py-1 pr-3">Action</th>
                  <th className="py-1">Detail</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="border-t border-line align-top">
                    <td className="whitespace-nowrap py-1.5 pr-3 text-xs text-mute">{when(r.at)}</td>
                    <td className={`py-1.5 pr-3 font-mono text-xs ${r.actor.startsWith("ai:") ? "text-brass" : "text-teal"}`}>
                      {r.actor}
                    </td>
                    <td className="py-1.5 pr-3">{r.client_id ?? ""}</td>
                    <td className="py-1.5 pr-3 font-mono text-xs">{r.action}</td>
                    <td className="break-all py-1.5 font-mono text-[11px] text-mute">{brief(r.detail)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
