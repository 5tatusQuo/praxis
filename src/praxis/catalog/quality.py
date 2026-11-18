"""The deterministic quality scorer.

Gives every rule a profile before any agent ranks it. The signals follow
PLAN.md ("Guardrails against weak and over-fitted rules"): specificity,
Pyramid of Pain tier, durability, upstream maturity, overlap with what is
already deployed, and (when a backtest is supplied) alert volume.
"""

from __future__ import annotations

import re
from typing import Any

from praxis.catalog.fingerprint import similarity

THRESHOLD = 60  # below this a pick needs a written justification or a waiver
NOISY_ALERTS_PER_DAY = 5.0

_HASH_FIELDS = ("hash", "imphash", "md5", "sha1", "sha256")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$")
_CVE = re.compile(r"cve[-_.]?\d{4}", re.IGNORECASE)
_BEHAVIOUR_FIELDS = (
    "process.command_line",
    "process.parent.command_line",
    "registry.path",
    "registry.data.strings",
    "file.path",
)


def pyramid_tier(triples: list[list[str]]) -> str:
    """Lowest tier the rule depends on: hash, ip, domain, tool or ttp."""
    fields = {t[0] for t in triples}
    values = [t[2] for t in triples]
    if fields and all(any(h in f for h in _HASH_FIELDS) for f in fields):
        return "hash"
    ip_values = [v for f, _, v in triples if f.endswith(".ip")]
    if ip_values and all(_IP.match(v) for v in ip_values) and not fields & set(_BEHAVIOUR_FIELDS):
        return "ip"
    domain_fields = {"destination.domain", "dns.question.name", "url.domain"}
    if values and fields <= domain_fields and all(_DOMAIN.match(v) for v in values):
        return "domain"
    if fields & set(_BEHAVIOUR_FIELDS):
        return "ttp"
    return "tool"


def profile(
    triples: list[list[str]],
    *,
    status: str = "",
    title: str = "",
    tags: list[str] | None = None,
    has_false_positive_notes: bool = False,
    references: int = 0,
    library: dict[str, list[list[str]]] | None = None,
    same_technique_in_library: int = 0,
    backtest: dict[str, Any] | None = None,
    has_positive_tests: bool = False,
) -> dict[str, Any]:
    """Score 0-100 with the reasons. Flags name what a reviewer should look at."""
    flags: list[str] = []
    fields = {t[0] for t in triples}
    values = [t[2] for t in triples]
    wildcard_ops = sum(1 for t in triples if t[1] not in ("equals", "==", "in", "in~"))
    shortest = min((len(v) for v in values), default=0)

    # Specificity: 0-30. Penalise both ends.
    specificity = 30
    if len(fields) <= 1 and values and wildcard_ops == len(triples) and shortest < 12:
        specificity = 5
        flags.append("too_generic: one field, short wildcard matches only")
    elif len(fields) <= 1:
        specificity = 18
        flags.append("single_field: relies on one field")
    exact = [t for t in triples if t[1] in ("equals", "==") and len(t[2]) > 24]
    if len(exact) >= 4 and len(exact) >= 0.7 * len(triples):
        specificity = min(specificity, 12)
        flags.append("too_narrow: mostly long exact-match literals")
    if not triples:
        specificity = 0
        flags.append("unparsed: logic could not be read")

    # Pyramid of Pain: 0-25.
    tier = pyramid_tier(triples) if triples else "tool"
    tier_points = {"ttp": 25, "tool": 15, "domain": 6, "ip": 4, "hash": 2}[tier]
    if tier in ("hash", "ip", "domain"):
        flags.append(f"ioc_tier: {tier}; belongs on the 90-day threat-watch list")

    # Durability: 0-10.
    durability = 10
    text = " ".join([title, *(tags or [])])
    if _CVE.search(text) and tier != "ttp":
        durability = 2
        flags.append("campaign_bound: tied to one CVE without behaviour; needs an expiry")
    elif _CVE.search(text):
        durability = 6

    # Upstream maturity: 0-15.
    maturity = {"stable": 12, "production": 12, "test": 9, "experimental": 4}.get(status, 6)
    if status in ("deprecated", "unsupported"):
        maturity = 0
        flags.append("deprecated upstream")
    if has_false_positive_notes:
        maturity += 2
    if references:
        maturity += 1
    if status == "experimental" and not has_false_positive_notes:
        flags.append("immature: experimental with no false-positive notes")
    maturity = min(maturity, 15)

    # Overlap with the deployed library: 0-10.
    overlap = 10
    closest, closest_id = 0.0, None
    for detection_id, other in (library or {}).items():
        score = similarity(triples, other)
        if score > closest:
            closest, closest_id = score, detection_id
    if closest >= 0.6:
        overlap = 0
        flags.append(f"duplicate: {closest:.0%} overlap with {closest_id}")
    elif same_technique_in_library >= 2:
        overlap = 4
        flags.append(f"crowded: {same_technique_in_library} rules already on this technique")

    # Backtest: 0-10. Without one the points are withheld, not assumed.
    volume = 0
    if backtest is not None:
        per_day = backtest["hits"] / max(backtest.get("days", 30), 1)
        if per_day > NOISY_ALERTS_PER_DAY:
            flags.append(f"noisy: {per_day:.1f} alerts a day on this client's data")
        elif backtest["hits"] == 0 and not has_positive_tests:
            volume = 5
            flags.append("unproven: no hits in the backtest and no positive test events")
        else:
            volume = 10
    else:
        flags.append("no_backtest")

    score = specificity + tier_points + durability + maturity + overlap + volume
    return {
        "score": score,
        "passes": score >= THRESHOLD and not any(f.startswith("duplicate") for f in flags),
        "tier": tier,
        "parts": {
            "specificity": specificity,
            "pyramid": tier_points,
            "durability": durability,
            "maturity": maturity,
            "overlap": overlap,
            "backtest": volume,
        },
        "closest_existing": closest_id,
        "closest_similarity": round(closest, 2),
        "flags": flags,
    }
