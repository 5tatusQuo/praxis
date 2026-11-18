import Link from "next/link";
import { api, type FleetRow, when } from "@/lib/api";
import { Panel } from "@/components/Stat";
import { canSee, currentSession } from "@/lib/session";

export const dynamic = "force-dynamic";

function Trend({ now, before }: { now: number; before: number | undefined }) {
  if (before === undefined || now === before) return null;
  const up = now > before;
  return (
    <span className={`ml-1 text-xs ${up ? "text-teal" : "text-ember"}`}>
      {up ? "▲" : "▼"} {Math.abs(now - before).toFixed(2)}
    </span>
  );
}

function Bar({ row }: { row: FleetRow }) {
  const s = row.summary;
  const parts: [number, string][] = [
    [s.covered, "var(--color-teal)"],
    [s.blind_rule, "var(--color-ember)"],
    [s.detection_gap, "var(--color-brass)"],
    [s.visibility_gap, "var(--color-unseen)"],
  ];
  return (
    <div className="flex h-2 w-full min-w-32 overflow-hidden rounded-full bg-obsidian">
      {parts.map(([count, colour], i) => (
        <div key={i} style={{ width: `${(100 * count) / s.techniques}%`, background: colour }} />
      ))}
    </div>
  );
}

export default async function Fleet() {
  const session = await currentSession();
  const fleet = ((await api<FleetRow[]>("/api/fleet")) ?? []).filter((row) => canSee(session, row.client_id));
  return (
    <div className="space-y-6">
      <div>
        <h1 className="font-display text-2xl font-semibold">Fleet</h1>
        <p className="text-sm text-mute">
          Every client&apos;s latest coverage snapshot. Numbers are measured by code from each
          SIEM, read-only.
        </p>
      </div>
      <Panel title="Clients" note={`${fleet.length} with a snapshot`}>
        {fleet.length === 0 ? (
          <p className="text-sm text-mute">
            No snapshots yet. Run <code className="font-mono">praxis coverage &lt;client&gt; --store</code>.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs uppercase tracking-wide text-mute">
                <tr>
                  <th className="py-2 pr-4">Client</th>
                  <th className="py-2 pr-4">Threat-weighted coverage</th>
                  <th className="py-2 pr-4">Visible</th>
                  <th className="py-2 pr-4">Techniques</th>
                  <th className="py-2 pr-4">Blind rules</th>
                  <th className="py-2 pr-4">Rules healthy</th>
                  <th className="py-2">Snapshot</th>
                </tr>
              </thead>
              <tbody>
                {fleet.map((row) => {
                  const s = row.summary;
                  const p = row.previous_summary ?? undefined;
                  const rules = s.rules.healthy + s.rules.blind + s.rules.disabled + (s.rules.shadow ?? 0);
                  return (
                    <tr key={row.client_id} className="border-t border-line align-middle">
                      <td className="py-3 pr-4">
                        <Link href={`/clients/${row.client_id}`} className="font-medium text-brass hover:underline">
                          {row.client_name}
                        </Link>
                        <div className="text-xs text-mute">{row.sector}</div>
                      </td>
                      <td className="py-3 pr-4">
                        {s.weighted_coverage_pct ?? "n/a"}%
                        <Trend now={s.weighted_coverage_pct ?? 0} before={p?.weighted_coverage_pct ?? undefined} />
                        <div className="text-xs text-mute">{s.coverage_pct}% unweighted</div>
                      </td>
                      <td className="py-3 pr-4">
                        {s.visible_pct}%
                        <Trend now={s.visible_pct} before={p?.visible_pct} />
                      </td>
                      <td className="py-3 pr-4">
                        <Bar row={row} />
                        <div className="mt-1 text-xs text-mute">
                          {s.covered} covered · {s.detection_gap} detection gaps · {s.visibility_gap} not visible
                        </div>
                      </td>
                      <td className={`py-3 pr-4 font-medium ${s.rules.blind ? "text-ember" : "text-mute"}`}>
                        {s.rules.blind}
                      </td>
                      <td className="py-3 pr-4">
                        {s.rules.healthy} / {rules}
                      </td>
                      <td className="py-3 text-xs text-mute">{when(row.taken_at)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
