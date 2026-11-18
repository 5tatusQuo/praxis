import Link from "next/link";
import { notFound } from "next/navigation";
import { Heatmap, Legend } from "@/components/Heatmap";
import { Panel, Stat } from "@/components/Stat";
import {
  api,
  CLASS_LABEL,
  type Diff,
  type GapClass,
  type HistoryRow,
  type Snapshot,
  type Technique,
  when,
} from "@/lib/api";

export const dynamic = "force-dynamic";

const FACTOR_LABEL: Record<string, string> = {
  presence: "events in the last 24h",
  stability: "data on 12 of 14 days",
  host_coverage: "80% of hosts reporting",
  field_population: "required fields 90% populated",
};

function Pips({ score }: { score: number }) {
  return (
    <span className="inline-flex gap-1" aria-label={`${score} of 4`}>
      {[1, 2, 3, 4].map((n) => (
        <span
          key={n}
          className="h-2 w-4 rounded-sm"
          style={{ background: n <= score ? "var(--color-teal)" : "var(--color-unseen)" }}
        />
      ))}
    </span>
  );
}

function GapTable({ rows, empty }: { rows: Technique[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-mute">{empty}</p>;
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-xs uppercase tracking-wide text-mute">
        <tr>
          <th className="py-1 pr-3">Technique</th>
          <th className="py-1 pr-3">Threat weight</th>
          <th className="py-1">Visibility</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((t) => (
          <tr key={t.id} className="border-t border-line">
            <td className="py-1.5 pr-3">
              <a
                className="font-mono text-xs text-brass hover:underline"
                href={`https://attack.mitre.org/techniques/${t.id.replace(".", "/")}/`}
              >
                {t.id}
              </a>{" "}
              {t.name}
            </td>
            <td className="py-1.5 pr-3">{t.weight.toFixed(2)}</td>
            <td className="py-1.5">
              <Pips score={t.visibility} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default async function ClientOverview({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const path = `/api/clients/${encodeURIComponent(id)}`;
  const [snapshot, history, diff] = await Promise.all([
    api<Snapshot>(`${path}/coverage`),
    api<HistoryRow[]>(`${path}/coverage/history?limit=10`),
    api<Diff>(`${path}/coverage/diff`),
  ]);
  if (!snapshot) notFound();
  const s = snapshot.summary;
  const blind = snapshot.rules.filter((r) => r.status === "blind");
  const silent = snapshot.components.filter((c) => c.silent);
  const unmapped = snapshot.sources.filter((x) => !x.mapped);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end gap-x-4 gap-y-2">
        <div>
          <Link href="/" className="text-xs text-mute hover:underline">
            ← Fleet
          </Link>
          <h1 className="font-display text-2xl font-semibold">{snapshot.client_name}</h1>
          <p className="text-sm text-mute">
            {snapshot.sector} · snapshot {when(snapshot.taken_at)} · ATT&amp;CK {snapshot.attack_version}
          </p>
        </div>
        <a
          href={`/clients/${id}/navigator`}
          className="ml-auto rounded-md border border-brass px-3 py-1.5 text-sm text-brass hover:bg-brass hover:text-obsidian"
        >
          Download Navigator layer
        </a>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat
          label="Threat-weighted coverage"
          value={`${s.weighted_coverage_pct ?? "n/a"}%`}
          hint={`${s.coverage_pct}% unweighted`}
          colour="var(--color-teal)"
        />
        <Stat label="Covered" value={s.covered} hint={`of ${s.techniques} techniques`} />
        <Stat label="Detection gaps" value={s.detection_gap} hint="visible, no rule" colour="var(--color-brass)" />
        <Stat label="Visibility gaps" value={s.visibility_gap} hint={`${s.visible_pct}% visible`} />
        <Stat
          label="Blind rules"
          value={s.rules.blind}
          hint={`${s.rules.healthy} healthy · ${s.rules.disabled} disabled`}
          colour={s.rules.blind ? "var(--color-ember)" : undefined}
        />
      </div>

      {blind.length > 0 || silent.length > 0 ? (
        <div className="rounded-lg border border-ember bg-slate px-4 py-3 text-sm">
          <div className="font-medium text-ember">Needs attention</div>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-fog">
            {silent.map((c) => (
              <li key={c.name}>
                <span className="font-mono text-xs">{c.table}</span> has sent nothing for 24 hours, so{" "}
                {c.name} is not visible.
              </li>
            ))}
            {blind.map((r) => (
              <li key={r.id}>
                {r.name ? `${r.name} ` : ""}
                <span className="font-mono text-xs">({r.id})</span> is deployed but blind
                {r.last_status !== "succeeded" ? ` (last run: ${r.last_status ?? "never ran"})` : " (its log source is silent)"}
                . It gives no coverage for {r.techniques.join(", ")}.
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <Panel title="ATT&CK coverage" note="One hex per technique, grouped by tactic. Hover for detail.">
        <div className="mb-4">
          <Legend />
        </div>
        <Heatmap techniques={snapshot.techniques} />
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Top detection gaps" note="Visible today, no rule. Ranked by threat weight for this sector.">
          <GapTable rows={snapshot.top_detection_gaps.slice(0, 12)} empty="No detection gaps." />
        </Panel>
        <Panel title="Top visibility gaps" note="Techniques this client cannot see. Fix telemetry first.">
          <GapTable rows={snapshot.top_visibility_gaps.slice(0, 12)} empty="No visibility gaps." />
        </Panel>
      </div>

      <Panel title="Visibility by data component" note="0 to 4: one point per factor, from the best log source.">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-mute">
              <tr>
                <th className="py-1 pr-3">Data component</th>
                <th className="py-1 pr-3">Score</th>
                <th className="py-1 pr-3">Log source</th>
                <th className="py-1 pr-3">Hosts</th>
                <th className="py-1">What is missing</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.components.map((c) => {
                const missing = Object.entries(c.factors)
                  .filter(([, ok]) => !ok)
                  .map(([k]) => FACTOR_LABEL[k] ?? k);
                return (
                  <tr key={c.name} className="border-t border-line">
                    <td className="py-1.5 pr-3">{c.name}</td>
                    <td className="py-1.5 pr-3">
                      <Pips score={c.score} />
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-xs">{c.table}</td>
                    <td className="py-1.5 pr-3">
                      {c.detail.hosts} / {c.detail.expected_hosts}
                    </td>
                    <td className={`py-1.5 text-xs ${c.silent ? "text-ember" : "text-mute"}`}>
                      {c.silent ? "Silent: no events in the last 24h" : missing.join("; ") || "Nothing"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel title="Deployed rules" note="Health as the SIEM reports it. Open a rule to tune it.">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-mute">
              <tr>
                <th className="py-1 pr-3">Rule</th>
                <th className="py-1 pr-3">Status</th>
                <th className="py-1 pr-3">Alerts 30d</th>
                <th className="py-1">Techniques</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.rules.map((r) => (
                <tr key={`${r.platform}-${r.id}`} className="border-t border-line">
                  <td className="py-1.5 pr-3 font-mono text-xs">
                    <Link href={`/clients/${id}/rules/${r.id}`} className="text-brass hover:underline">
                      {r.id}
                    </Link>
                    {r.name ? <div className="font-sans text-sm text-fog">{r.name}</div> : null}
                  </td>
                  <td
                    className={`py-1.5 pr-3 ${
                      r.status === "healthy" ? "text-teal" : r.status === "blind" ? "text-ember" : "text-mute"
                    }`}
                  >
                    {r.status}
                  </td>
                  <td className="py-1.5 pr-3">{r.alerts_30d}</td>
                  <td className="py-1.5 font-mono text-xs">{r.techniques.join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Log sources" note="Tables seen in the last 14 days.">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-mute">
              <tr>
                <th className="py-1 pr-3">Table</th>
                <th className="py-1 pr-3">Events 14d</th>
                <th className="py-1 pr-3">Hosts</th>
                <th className="py-1">Last event</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.sources.map((x) => (
                <tr key={x.table} className="border-t border-line">
                  <td className="py-1.5 pr-3 font-mono text-xs">
                    {x.table}
                    {!x.mapped ? <span className="ml-2 text-brass">no schema note</span> : null}
                  </td>
                  <td className="py-1.5 pr-3">{x.events_14d.toLocaleString("en")}</td>
                  <td className="py-1.5 pr-3">{x.hosts}</td>
                  <td className={`py-1.5 text-xs ${x.events_24h === 0 ? "text-ember" : "text-mute"}`}>
                    {x.last_event ? when(x.last_event) : "never"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {unmapped.length > 0 ? (
            <p className="mt-3 text-xs text-mute">
              Tables without a schema note in the data map do not count towards visibility yet.
            </p>
          ) : null}
        </Panel>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Panel
          title="Changes since the previous snapshot"
          note={diff?.from ? `${when(diff.from)} → ${when(diff.to)}` : "No earlier snapshot"}
        >
          {!diff || diff.changes.length === 0 ? (
            <p className="text-sm text-mute">No technique changed class.</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {diff.changes.slice(0, 15).map((c) => (
                <li key={c.id}>
                  <span className="font-mono text-xs text-brass">{c.id}</span> {c.name}:{" "}
                  <span className="text-mute">{CLASS_LABEL[c.from as GapClass] ?? c.from}</span> →{" "}
                  {CLASS_LABEL[c.to as GapClass] ?? c.to}
                </li>
              ))}
              {diff.changes.length > 15 ? (
                <li className="text-xs text-mute">and {diff.changes.length - 15} more</li>
              ) : null}
            </ul>
          )}
        </Panel>
        <Panel title="Snapshot history" note="Most recent first.">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase tracking-wide text-mute">
              <tr>
                <th className="py-1 pr-3">Taken</th>
                <th className="py-1 pr-3">Weighted</th>
                <th className="py-1 pr-3">Covered</th>
                <th className="py-1">Blind rules</th>
              </tr>
            </thead>
            <tbody>
              {(history ?? []).map((h) => (
                <tr key={h.id} className="border-t border-line">
                  <td className="py-1.5 pr-3 text-xs text-mute">{when(h.taken_at)}</td>
                  <td className="py-1.5 pr-3">{h.summary.weighted_coverage_pct ?? "n/a"}%</td>
                  <td className="py-1.5 pr-3">{h.summary.covered}</td>
                  <td className="py-1.5">{h.summary.rules.blind}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      </div>
    </div>
  );
}
