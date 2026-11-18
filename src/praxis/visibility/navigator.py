"""ATT&CK Navigator layers from a coverage snapshot."""

from __future__ import annotations

from typing import Any

from praxis import attack

# PRAXIS palette: teal covered, brass detection gap, ember blind rule, slate not visible.
CLASS_COLOURS = {
    "covered": "#2EC4B6",
    "detection_gap": "#D4A24C",
    "blind_rule": "#E5533D",
    "visibility_gap": "#3A4553",
}
CLASS_LABELS = {
    "covered": "Covered: visible, healthy rule",
    "detection_gap": "Detection gap: visible, no rule",
    "blind_rule": "Blind rule: deployed but cannot see or run",
    "visibility_gap": "Visibility gap: not visible",
}


def coverage_layer(snapshot: dict[str, Any]) -> dict[str, Any]:
    major = attack.version().split(".")[0]
    techniques = []
    for technique in snapshot["techniques"]:
        comment = CLASS_LABELS[technique["class"]]
        if technique["rules"]:
            comment += f" ({', '.join(technique['rules'])})"
        for tactic in technique["tactics"]:
            techniques.append(
                {
                    "techniqueID": technique["id"],
                    "tactic": attack.bundle()["tactics"][tactic]["shortname"],
                    "color": CLASS_COLOURS[technique["class"]],
                    "score": technique["visibility"],
                    "comment": comment,
                    "enabled": True,
                    "metadata": [
                        {"name": "threat weight", "value": str(technique["weight"])},
                        {"name": "visibility (0-4)", "value": str(technique["visibility"])},
                    ],
                }
            )
    return {
        "name": f"PRAXIS coverage: {snapshot['client']}",
        "versions": {"attack": major, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Coverage snapshot taken {snapshot['taken_at']}. Colour is the gap "
        "class; score is visibility 0-4.",
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "legendItems": [
            {"label": CLASS_LABELS[k], "color": CLASS_COLOURS[k]} for k in CLASS_COLOURS
        ],
        "showTacticRowBackground": False,
        "selectSubtechniquesWithParent": False,
    }
