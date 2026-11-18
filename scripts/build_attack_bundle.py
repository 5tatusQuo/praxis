"""Build src/praxis/data/attack.json from MITRE's enterprise ATT&CK STIX bundle.

    uv run scripts/build_attack_bundle.py path/to/enterprise-attack.json

Download the STIX file from https://github.com/mitre-attack/attack-stix-data
(enterprise-attack/enterprise-attack-<version>.json). The output keeps only
what PRAXIS needs, so the matrix can ship inside the package.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src/praxis/data/attack.json"


def external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def main(stix_path: str) -> None:
    objects = json.loads(Path(stix_path).read_text())["objects"]
    version = next(o["x_mitre_version"] for o in objects if o["type"] == "x-mitre-collection")
    by_stix_id = {o["id"]: o for o in objects}

    tactics, shortname_to_id = {}, {}
    for o in objects:
        if o["type"] == "x-mitre-tactic" and live(o):
            tactics[external_id(o)] = {"name": o["name"], "shortname": o["x_mitre_shortname"]}
            shortname_to_id[o["x_mitre_shortname"]] = external_id(o)

    techniques = {}
    for o in objects:
        if o["type"] == "attack-pattern" and live(o):
            techniques[external_id(o)] = {
                "name": o["name"],
                "tactics": sorted(
                    shortname_to_id[p["phase_name"]]
                    for p in o.get("kill_chain_phases", [])
                    if p["kill_chain_name"] == "mitre-attack"
                ),
                "platforms": sorted(o.get("x_mitre_platforms", [])),
                "data_components": [],
            }

    # Data components that detect each technique. ATT&CK 18+ links them through
    # detection strategies and analytics; older releases use a direct
    # `detects` relationship from the data component. Handle both.
    components = {
        o["id"]: o["name"] for o in objects if o["type"] == "x-mitre-data-component" and live(o)
    }
    found: dict[str, set[str]] = {t: set() for t in techniques}
    for o in objects:
        if o["type"] != "relationship" or o.get("relationship_type") != "detects" or not live(o):
            continue
        target = by_stix_id.get(o["target_ref"])
        source = by_stix_id.get(o["source_ref"])
        if not target or not source or external_id(target) not in found:
            continue
        if source["type"] == "x-mitre-data-component":
            found[external_id(target)].add(source["name"])
        elif source["type"] == "x-mitre-detection-strategy":
            for analytic_id in source.get("x_mitre_analytic_refs", []):
                analytic = by_stix_id.get(analytic_id, {})
                for ref in analytic.get("x_mitre_log_source_references", []):
                    name = components.get(ref.get("x_mitre_data_component_ref"))
                    if name:
                        found[external_id(target)].add(name)
    for technique_id, names in found.items():
        techniques[technique_id]["data_components"] = sorted(names)

    # Groups and the techniques they are reported to use. A sub-technique also
    # counts for its parent.
    groups = {}
    for o in objects:
        if o["type"] == "intrusion-set" and live(o):
            groups[o["id"]] = {
                "id": external_id(o),
                "name": o["name"],
                "aliases": [a for a in o.get("aliases", []) if a != o["name"]],
                "description": " ".join(o.get("description", "").split())[:700],
                "techniques": set(),
            }
    for o in objects:
        if o["type"] != "relationship" or o.get("relationship_type") != "uses" or not live(o):
            continue
        group = groups.get(o["source_ref"])
        target = by_stix_id.get(o["target_ref"])
        if group and target and target["type"] == "attack-pattern":
            technique_id = external_id(target)
            if technique_id in techniques:
                group["techniques"].update({technique_id, technique_id.split(".")[0]})
    groups_out = {
        g["id"]: {
            "name": g["name"],
            "aliases": g["aliases"],
            "description": g["description"],
            "techniques": sorted(g["techniques"]),
        }
        for g in sorted(groups.values(), key=lambda g: g["id"])
    }

    OUT.write_text(
        json.dumps(
            {
                "version": version,
                "tactics": dict(sorted(tactics.items())),
                "techniques": dict(sorted(techniques.items())),
                "data_components": sorted(set(components.values())),
                "groups": groups_out,
            },
            indent=1,
            sort_keys=False,
        )
        + "\n"
    )
    with_dc = sum(1 for t in techniques.values() if t["data_components"])
    print(
        f"ATT&CK {version}: {len(tactics)} tactics, {len(techniques)} techniques "
        f"({with_dc} with data components), {len(components)} data components, "
        f"{len(groups_out)} groups -> {OUT}"
    )


if __name__ == "__main__":
    main(sys.argv[1])
