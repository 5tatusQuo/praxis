import Link from "next/link";
import { notFound } from "next/navigation";
import { OverrideEditor } from "@/components/OverrideEditor";
import { Panel, Stat } from "@/components/Stat";
import { api, type RuleDetail } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function TuningStudio({ params }: { params: Promise<{ id: string; rule: string }> }) {
  const { id, rule } = await params;
  const detail = await api<RuleDetail>(`/api/clients/${encodeURIComponent(id)}/rules/${encodeURIComponent(rule)}`);
  if (!detail) notFound();
  const alerts = detail.alerts;
  const sample = alerts.samples?.[0] ?? null;
  return (
    <div className="space-y-6">
      <div>
        <Link href={`/clients/${id}`} className="text-xs text-mute hover:underline">
          ← {id}
        </Link>
        <h1 className="font-display text-2xl font-semibold">Tuning studio</h1>
        <p className="text-sm text-mute">
          <span className="font-mono">{detail.detection}</span> {detail.name}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Alerts, 30 days" value={alerts.alerts ?? "n/a"} hint={alerts.error ? "SIEM not reachable" : undefined} />
        <Stat label="Severity" value={detail.envelope.severity} hint={`every ${detail.envelope.interval}`} />
        <Stat label="State" value={detail.envelope.enabled ? "enabled" : "disabled"} />
        <Stat
          label="Tuning"
          value={detail.tuning ? `${detail.tuning.exclude.length} exclusion(s)` : "none"}
          hint={detail.tuning?.expires ? `expires ${detail.tuning.expires}` : undefined}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <Panel title="Alerts" note="Grouped by field. Users and hosts are pseudonymised.">
          {alerts.error ? (
            <p className="text-sm text-ember">{alerts.error}</p>
          ) : Object.keys(alerts.top_values ?? {}).length === 0 ? (
            <p className="text-sm text-mute">No alerts in the last 30 days.</p>
          ) : (
            <div className="space-y-3 text-sm">
              {Object.entries(alerts.top_values ?? {}).map(([field, values]) => (
                <div key={field}>
                  <div className="font-mono text-xs text-mute">{field}</div>
                  <ul>
                    {values.map((v) => (
                      <li key={v.value} className="flex justify-between gap-3">
                        <span className="break-all font-mono text-xs">{v.value}</span>
                        <span>{v.alerts}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Rendered rule" note={`${detail.language.toUpperCase()} · ${detail.envelope.index.join(", ")}`}>
          <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs leading-relaxed">{detail.query}</pre>
          {detail.tuning ? (
            <div className="mt-4 border-t border-line pt-3 text-sm">
              <div className="text-xs uppercase tracking-wide text-mute">Current tuning</div>
              <p className="mt-1">{detail.tuning.reason}</p>
              <ul className="mt-1 font-mono text-xs">
                {detail.tuning.exclude.map((e, i) => (
                  <li key={i}>
                    {e.field} {e.op} {String(e.value)}
                    {(e.also ?? []).map((c) => ` and ${c.field} ${c.op} ${String(c.value)}`).join("")}
                  </li>
                ))}
              </ul>
              <p className="mt-1 text-xs text-mute">
                {detail.tuning.author} · evidence {detail.tuning.evidence.join(", ")}
              </p>
            </div>
          ) : null}
        </Panel>

        <Panel title="Try an exclusion" note="Measured in the lab and on 30 days of this client's data.">
          <OverrideEditor client={id} rule={rule} sample={sample} />
        </Panel>
      </div>
    </div>
  );
}
