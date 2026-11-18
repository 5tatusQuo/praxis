import { requireAdmin } from "@/lib/admin";
import Link from "next/link";
import { Panel } from "@/components/Stat";
import { api, when } from "@/lib/api";

export const dynamic = "force-dynamic";

type HuntRow = { id: string; prompt: string; clients: string[]; hypotheses: number; created_at: string };

export default async function Hunts() {
  await requireAdmin();
  const hunts = (await api<HuntRow[]>("/api/hunts")) ?? [];
  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold">Hunts</h1>
        <p className="text-sm text-mute">
          Threat-driven hunts. The Hunt Planner turns a prompt into hypotheses and runs each query
          read-only against the clients in scope. Durable hypotheses become detections.
        </p>
      </div>
      <Panel title="Hunt workspace" note={`${hunts.length} so far`}>
        {hunts.length === 0 ? (
          <p className="text-sm text-mute">
            None yet. Run <code className="font-mono">praxis hunt &quot;actor or behaviour&quot; --sector healthcare</code>.
          </p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-mute">
              <tr>
                <th className="py-2 pr-4">Threat</th>
                <th className="py-2 pr-4">Clients</th>
                <th className="py-2 pr-4">Hypotheses</th>
                <th className="py-2">Run</th>
              </tr>
            </thead>
            <tbody>
              {hunts.map((h) => (
                <tr key={h.id} className="border-t border-line">
                  <td className="py-2 pr-4">
                    <Link href={`/hunts/${h.id}`} className="text-brass hover:underline">
                      {h.prompt}
                    </Link>
                  </td>
                  <td className="py-2 pr-4">{h.clients.join(", ")}</td>
                  <td className="py-2 pr-4">{h.hypotheses}</td>
                  <td className="py-2 text-xs text-mute">{when(h.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
