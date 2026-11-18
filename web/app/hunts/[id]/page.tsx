import { requireAdmin } from "@/lib/admin";
import Link from "next/link";
import { notFound } from "next/navigation";
import { Panel } from "@/components/Stat";
import { api } from "@/lib/api";

export const dynamic = "force-dynamic";

type Hypothesis = {
  title: string;
  technique: string;
  rationale: string;
  query: string;
  assessment: string;
  durable: boolean;
  tested: boolean;
  results: Record<string, { hits: number; days: number }>;
};
type Hunt = { id: string; prompt: string; clients: string[]; summary: string; hypotheses: Hypothesis[]; pr_url: string | null };

export default async function HuntDetail({ params }: { params: Promise<{ id: string }> }) {
  await requireAdmin();
  const { id } = await params;
  const hunt = await api<Hunt>(`/api/hunts/${encodeURIComponent(id)}`);
  if (!hunt) notFound();
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end gap-x-4 gap-y-2">
        <div>
          <Link href="/hunts" className="text-xs text-mute hover:underline">
            ← Hunts
          </Link>
          <h1 className="font-display text-2xl font-semibold">{hunt.prompt}</h1>
          <p className="text-sm text-mute">Clients in scope: {hunt.clients.join(", ")}</p>
        </div>
        {hunt.pr_url ? (
          <a href={hunt.pr_url} className="ml-auto rounded-md border border-brass px-3 py-1.5 text-sm text-brass hover:bg-brass hover:text-obsidian">
            Open the pull request
          </a>
        ) : null}
      </div>
      <Panel title="Summary" note="Written by the Hunt Planner.">
        <p className="whitespace-pre-line text-sm leading-relaxed">{hunt.summary}</p>
      </Panel>
      {hunt.hypotheses.map((h, i) => (
        <Panel key={i} title={h.title} note={`${h.technique}${h.durable ? " · durable: candidate detection" : ""}`}>
          <div className="grid gap-5 text-sm lg:grid-cols-3">
            <div className="space-y-3 lg:col-span-2">
              <p className="leading-relaxed text-mute">{h.rationale}</p>
              <pre className="overflow-x-auto whitespace-pre-wrap rounded bg-obsidian p-3 font-mono text-xs">{h.query}</pre>
              <p className="whitespace-pre-line leading-relaxed">{h.assessment}</p>
            </div>
            <div>
              <div className="text-xs uppercase tracking-wide text-mute">Hits, last 30 days</div>
              {h.tested ? (
                <ul className="mt-1">
                  {Object.entries(h.results).map(([client, r]) => (
                    <li key={client} className="flex justify-between border-t border-line py-1">
                      <span>{client}</span>
                      <span className={r.hits > 0 ? "font-semibold text-brass" : "text-mute"}>{r.hits}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="mt-1 text-ember">This query was never run.</p>
              )}
              <p className="mt-2 text-xs text-mute">Counts are recorded by code from the queries that ran.</p>
            </div>
          </div>
        </Panel>
      ))}
    </div>
  );
}
