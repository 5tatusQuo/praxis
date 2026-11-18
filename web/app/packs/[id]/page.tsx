import Link from "next/link";
import { notFound } from "next/navigation";
import { Panel, Stat } from "@/components/Stat";
import { api, type Pack } from "@/lib/api";

export const dynamic = "force-dynamic";

const PART_LABEL: Record<string, [string, number]> = {
  specificity: ["Specificity", 30],
  pyramid: ["Pyramid of Pain", 25],
  maturity: ["Upstream maturity", 15],
  durability: ["Durability", 10],
  overlap: ["No overlap", 10],
  backtest: ["Backtest", 10],
};
const SEVERITY_COLOUR: Record<string, string> = {
  blocker: "text-ember",
  concern: "text-brass",
  note: "text-mute",
};

export default async function PackReview({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const pack = await api<Pack>(`/api/packs/${encodeURIComponent(id)}`);
  if (!pack) notFound();
  const review = pack.review;
  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end gap-x-4 gap-y-2">
        <div>
          <Link href="/packs" className="text-xs text-mute hover:underline">
            ← Rule packs
          </Link>
          <h1 className="font-display text-2xl font-semibold">{pack.id}</h1>
          <p className="text-sm text-mute">
            Candidate pack for{" "}
            <Link href={`/clients/${pack.client}`} className="text-brass hover:underline">
              {pack.client}
            </Link>{" "}
            · {pack.month} · {pack.agents.model ?? "agent"}
          </p>
        </div>
        {pack.pr_url ? (
          <a
            href={pack.pr_url}
            className="ml-auto rounded-md border border-brass px-3 py-1.5 text-sm text-brass hover:bg-brass hover:text-obsidian"
          >
            Review and merge on GitHub
          </a>
        ) : null}
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Detections" value={pack.picks.length} hint={`budget ${pack.budget}`} />
        <Stat
          label="Reviewer agent"
          value={review ? review.verdict.toUpperCase() : "n/a"}
          colour={review?.verdict === "pass" ? "var(--color-teal)" : "var(--color-ember)"}
          hint="independent, no authoring context"
        />
        <Stat label="Dropped by guardrails" value={pack.rejected.length} hint="enforced in code" />
        <Stat
          label="Agent work"
          value={`${pack.usage.llm_calls ?? 0} calls`}
          hint={`${pack.usage.tool_calls ?? 0} tool calls`}
        />
      </div>

      <Panel title="Gap brief" note="Written by the Curator from the coverage snapshot.">
        <p className="whitespace-pre-line text-sm leading-relaxed">{pack.brief}</p>
      </Panel>

      {pack.picks.map((pick) => (
        <Panel
          key={pick.detection}
          title={`${pick.detection} closes ${pick.technique}`}
          note={`threat weight ${pick.weight.toFixed(2)} · from ${pick.candidate}`}
        >
          <div className="grid gap-5 lg:grid-cols-3">
            <div className="space-y-3 text-sm lg:col-span-2">
              <div>
                <div className="text-xs uppercase tracking-wide text-mute">Why this rule</div>
                <p className="whitespace-pre-line leading-relaxed">{pick.rationale}</p>
              </div>
              {pick.justification ? (
                <div>
                  <div className="text-xs uppercase tracking-wide text-brass">
                    Justification for a low score
                  </div>
                  <p className="whitespace-pre-line leading-relaxed">{pick.justification}</p>
                </div>
              ) : null}
              {pick.engineer_notes ? (
                <div>
                  <div className="text-xs uppercase tracking-wide text-mute">Engineer notes</div>
                  <p className="whitespace-pre-line leading-relaxed text-mute">{pick.engineer_notes}</p>
                </div>
              ) : null}
              {(review?.comments ?? [])
                .filter((c) => c.detection_id === pick.detection)
                .map((c, i) => (
                  <div key={i} className="rounded border border-line bg-obsidian px-3 py-2">
                    <span className={`text-xs uppercase ${SEVERITY_COLOUR[c.severity] ?? ""}`}>
                      Reviewer {c.severity}
                    </span>
                    <p className="leading-relaxed">{c.comment}</p>
                  </div>
                ))}
            </div>
            <div className="text-sm">
              <div className="flex items-baseline gap-2">
                <span className="font-display text-3xl font-semibold">{pick.quality.score}</span>
                <span className="text-xs text-mute">/ 100 · {pick.quality.tier} tier</span>
              </div>
              <ul className="mt-2 space-y-1.5">
                {Object.entries(PART_LABEL).map(([key, [label, max]]) => {
                  const value = pick.quality.parts[key] ?? 0;
                  return (
                    <li key={key}>
                      <div className="flex justify-between text-xs text-mute">
                        <span>{label}</span>
                        <span>
                          {value}/{max}
                        </span>
                      </div>
                      <div className="h-1.5 rounded-full bg-obsidian">
                        <div
                          className="h-1.5 rounded-full bg-teal"
                          style={{ width: `${(100 * value) / max}%` }}
                        />
                      </div>
                    </li>
                  );
                })}
              </ul>
              <dl className="mt-3 space-y-1 text-xs">
                <div className="flex justify-between">
                  <dt className="text-mute">Backtest, 30 days</dt>
                  <dd>{pick.quality.backtest ? `${pick.quality.backtest.hits} hits` : "n/a"}</dd>
                </div>
                <div className="flex justify-between">
                  <dt className="text-mute">Lab replay</dt>
                  <dd className={pick.lab.passed ? "text-teal" : "text-ember"}>
                    {pick.lab.cases} cases {pick.lab.passed ? "pass" : "fail"}
                  </dd>
                </div>
              </dl>
              {pick.quality.flags.length > 0 ? (
                <ul className="mt-3 list-disc space-y-1 pl-4 text-xs text-brass">
                  {pick.quality.flags.map((f) => (
                    <li key={f}>{f}</li>
                  ))}
                </ul>
              ) : null}
            </div>
          </div>
        </Panel>
      ))}

      {review ? (
        <Panel title={`Reviewer agent: ${review.verdict}`} note="A separate agent with read-only tools.">
          <p className="whitespace-pre-line text-sm leading-relaxed">{review.summary}</p>
          {review.comments.filter((c) => !pack.picks.some((p) => p.detection === c.detection_id)).length > 0 ? (
            <ul className="mt-3 space-y-1 text-sm">
              {review.comments
                .filter((c) => !pack.picks.some((p) => p.detection === c.detection_id))
                .map((c, i) => (
                  <li key={i}>
                    <span className={`text-xs uppercase ${SEVERITY_COLOUR[c.severity] ?? ""}`}>{c.severity}</span>{" "}
                    {c.comment}
                  </li>
                ))}
            </ul>
          ) : null}
        </Panel>
      ) : null}

      {pack.rejected.length > 0 ? (
        <Panel title="Dropped by the guardrails" note="Rules the code refused, whatever the agent argued.">
          <ul className="space-y-1 text-sm">
            {pack.rejected.map((r, i) => (
              <li key={i}>
                <span className="font-mono text-xs text-mute">{r.candidate}</span>: {r.reason}
              </li>
            ))}
          </ul>
        </Panel>
      ) : null}
    </div>
  );
}
