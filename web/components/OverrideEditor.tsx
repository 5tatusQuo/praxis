"use client";

import { useState } from "react";
import type { Preview } from "@/lib/api";

const OPS = ["equals", "endswith", "startswith", "contains", "wildcard"];

// The override editor: one exclusion and an example event, with a live,
// deterministic impact preview from the lab and a 30-day backtest.
export function OverrideEditor({ client, rule, sample }: { client: string; rule: string; sample: object | null }) {
  const [field, setField] = useState("process.parent.executable");
  const [op, setOp] = useState("endswith");
  const [value, setValue] = useState("");
  const [example, setExample] = useState(sample ? JSON.stringify(sample, null, 2) : "");
  const [preview, setPreview] = useState<Preview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setError(null);
    setPreview(null);
    try {
      const examples = example.trim() ? [JSON.parse(example)] : [];
      const response = await fetch(`/clients/${client}/rules/${rule}/preview`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ exclude: [{ field, op, value }], examples }),
      });
      const body = await response.json();
      if (!response.ok || body.error) throw new Error(body.error ?? `Preview failed (${response.status})`);
      setPreview(body as Preview);
    } catch (e) {
      setError(e instanceof SyntaxError ? "The example event is not valid JSON." : String(e));
    } finally {
      setBusy(false);
    }
  }

  const yaml = `exclude:\n  - field: ${field}\n    op: ${op}\n    value: '${value}'`;
  const input = "w-full rounded border border-line bg-obsidian px-2 py-1.5 font-mono text-xs text-fog";
  return (
    <div className="space-y-3 text-sm">
      <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
        <label className="block">
          <span className="text-xs text-mute">Field</span>
          <input className={input} value={field} onChange={(e) => setField(e.target.value)} />
        </label>
        <label className="block">
          <span className="text-xs text-mute">Operator</span>
          <select className={input} value={op} onChange={(e) => setOp(e.target.value)}>
            {OPS.map((o) => (
              <option key={o}>{o}</option>
            ))}
          </select>
        </label>
      </div>
      <label className="block">
        <span className="text-xs text-mute">Value (case-sensitive)</span>
        <input className={input} value={value} onChange={(e) => setValue(e.target.value)} placeholder="\Vendor\agent.exe" />
      </label>
      <label className="block">
        <span className="text-xs text-mute">Example event this should silence (JSON)</span>
        <textarea className={`${input} h-40`} value={example} onChange={(e) => setExample(e.target.value)} />
      </label>
      <button
        onClick={run}
        disabled={busy || !value}
        className="rounded-md border border-brass px-3 py-1.5 text-brass hover:bg-brass hover:text-obsidian disabled:opacity-40"
      >
        {busy ? "Measuring…" : "Preview impact"}
      </button>
      {error ? <p className="text-ember">{error}</p> : null}
      {preview ? (
        <div className="space-y-2 rounded border border-line bg-obsidian p-3">
          <p>
            Suppresses <span className="font-semibold text-brass">{preview.suppressed}</span> of{" "}
            {preview.matches_before} matches over {preview.days} days.
          </p>
          <p className={preview.positives_still_fire ? "text-teal" : "text-ember"}>
            {preview.positives.filter((p) => p.fires).length} of {preview.positives.length} positive tests still fire
            {preview.positives_still_fire ? "." : ": this exclusion blinds the rule."}
          </p>
          {preview.examples.length > 0 ? (
            <p className={preview.examples_silenced ? "text-teal" : "text-ember"}>
              {preview.examples_silenced
                ? "The example fires untuned and is silenced once tuned."
                : preview.examples[0].fires_untuned
                  ? "The example still fires with this exclusion."
                  : "The example does not fire on the untuned rule, so it proves nothing."}
            </p>
          ) : (
            <p className="text-mute">Add an example event: CI requires one for every exclusion.</p>
          )}
          <pre className="overflow-x-auto pt-1 font-mono text-xs text-mute">{yaml}</pre>
          <p className="text-xs text-mute">
            To propose it, add this to <code>clients/{client}/tuning/{rule}.yml</code> in a pull request, or run{" "}
            <code>praxis tune {rule} --client {client}</code> to have the Tuner agent draft it.
          </p>
        </div>
      ) : null}
    </div>
  );
}
