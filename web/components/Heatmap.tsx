import { CLASS_COLOUR, CLASS_HELP, CLASS_LABEL, type GapClass, type Technique } from "@/lib/api";
import { TACTICS } from "@/lib/tactics";

const ORDER: GapClass[] = ["covered", "blind_rule", "detection_gap", "visibility_gap"];

export function Legend() {
  return (
    <ul className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-mute">
      {ORDER.map((k) => (
        <li key={k} className="flex items-center gap-2">
          <span className="hex" style={{ background: CLASS_COLOUR[k] }} />
          <span>
            <span className="text-fog">{CLASS_LABEL[k]}</span>: {CLASS_HELP[k]}
          </span>
        </li>
      ))}
    </ul>
  );
}

// One column per tactic, one hex per technique, most interesting first.
export function Heatmap({ techniques }: { techniques: Technique[] }) {
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-5 sm:grid-cols-4 lg:grid-cols-7">
      {TACTICS.map(([id, name]) => {
        const cells = techniques
          .filter((t) => t.tactics.includes(id))
          .sort(
            (a, b) =>
              ORDER.indexOf(a.class) - ORDER.indexOf(b.class) || b.weight - a.weight || a.id.localeCompare(b.id),
          );
        const covered = cells.filter((t) => t.class === "covered").length;
        return (
          <div key={id}>
            <div className="text-xs font-medium text-fog">{name}</div>
            <div className="mb-2 text-[11px] text-mute">
              {covered} of {cells.length} covered
            </div>
            <div className="flex flex-wrap gap-[3px]">
              {cells.map((t) => (
                <span
                  key={t.id}
                  className="hex"
                  style={{ background: CLASS_COLOUR[t.class] }}
                  title={`${t.id} ${t.name}\n${CLASS_LABEL[t.class]} · visibility ${t.visibility}/4 · threat weight ${t.weight}${
                    t.rules.length ? `\n${t.rules.join(", ")}` : ""
                  }`}
                />
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}
