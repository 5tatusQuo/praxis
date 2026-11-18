export function Stat({
  label,
  value,
  hint,
  colour,
}: {
  label: string;
  value: string | number;
  hint?: string;
  colour?: string;
}) {
  return (
    <div className="rounded-lg border border-line bg-slate px-4 py-3">
      <div className="text-xs uppercase tracking-wide text-mute">{label}</div>
      <div className="font-display text-2xl font-semibold" style={colour ? { color: colour } : undefined}>
        {value}
      </div>
      {hint ? <div className="text-xs text-mute">{hint}</div> : null}
    </div>
  );
}

export function Panel({ title, note, children }: { title: string; note?: string; children: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-line bg-slate">
      <div className="flex flex-wrap items-baseline gap-x-3 border-b border-line px-4 py-3">
        <h2 className="font-display text-base font-semibold text-fog">{title}</h2>
        {note ? <p className="text-xs text-mute">{note}</p> : null}
      </div>
      <div className="p-4">{children}</div>
    </section>
  );
}
