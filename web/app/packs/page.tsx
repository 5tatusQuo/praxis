import { requireAdmin } from "@/lib/admin";
import Link from "next/link";
import { Panel } from "@/components/Stat";
import { api, type PackRow, when } from "@/lib/api";

export const dynamic = "force-dynamic";

export function Verdict({ verdict }: { verdict: string | null }) {
  if (!verdict) return <span className="text-mute">not reviewed</span>;
  return <span className={verdict === "pass" ? "text-teal" : "text-ember"}>{verdict}</span>;
}

export default async function Packs() {
  await requireAdmin();
  const packs = (await api<PackRow[]>("/api/packs")) ?? [];
  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold">Rule packs</h1>
        <p className="text-sm text-mute">
          Monthly proposals from the Curator agent. Each one is a pull request: agents propose,
          CI tests, a person approves, and only then does the pipeline deploy.
        </p>
      </div>
      <Panel title="Proposals" note={`${packs.length} so far`}>
        {packs.length === 0 ? (
          <p className="text-sm text-mute">
            None yet. Run{" "}
            <code className="font-mono">praxis pack plan &lt;client&gt; --month YYYY-MM</code>.
          </p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-mute">
              <tr>
                <th className="py-2 pr-4">Pack</th>
                <th className="py-2 pr-4">Client</th>
                <th className="py-2 pr-4">Detections</th>
                <th className="py-2 pr-4">Reviewer agent</th>
                <th className="py-2 pr-4">Status</th>
                <th className="py-2">Proposed</th>
              </tr>
            </thead>
            <tbody>
              {packs.map((p) => (
                <tr key={p.id} className="border-t border-line">
                  <td className="py-2 pr-4">
                    <Link href={`/packs/${p.id}`} className="font-mono text-brass hover:underline">
                      {p.id}
                    </Link>
                  </td>
                  <td className="py-2 pr-4">{p.client_id}</td>
                  <td className="py-2 pr-4">{p.picks}</td>
                  <td className="py-2 pr-4">
                    <Verdict verdict={p.verdict} />
                  </td>
                  <td className="py-2 pr-4">{p.status}</td>
                  <td className="py-2 text-xs text-mute">{when(p.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
