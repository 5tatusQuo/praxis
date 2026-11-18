"""Synthetic telemetry for fictional clients, so the lab has something to measure.

Driven by `clients/<id>/lab/telemetry.yml` and the sample events in the
datamap catalog. Deterministic for a given client, source and time window.
"""

from __future__ import annotations

import copy
import random
from datetime import UTC, datetime, timedelta

from praxis.content.loader import ContentRepo
from praxis.content.models import Client, LabSource
from praxis.platforms import get_platform

WINDOW = timedelta(days=14)


def _drop(event: dict, dotted: str) -> None:
    parts = dotted.split(".")
    node = event
    for part in parts[:-1]:
        node = node.get(part)
        if not isinstance(node, dict):
            return
    node.pop(parts[-1], None)


def generate(
    client: Client, spec: LabSource, sample: dict, start: datetime, end: datetime
) -> list[dict]:
    """Events for one source between start and end, spread evenly at random."""
    seconds = (end - start).total_seconds()
    if seconds <= 0:
        return []
    count = int(spec.events_per_day * seconds / 86400)
    rng = random.Random(f"{client.id}:{spec.source}:{start.isoformat()}")
    events = []
    for _ in range(count):
        event = copy.deepcopy(sample)
        when = start + timedelta(seconds=rng.uniform(0, seconds))
        event["@timestamp"] = when.isoformat().replace("+00:00", "Z")
        host = f"{client.id}-host-{rng.randrange(spec.hosts) + 1:03d}"
        event.setdefault("host", {})["name"] = host
        # Marks generated events, so a top-up continues from the last generated
        # one and ignores replayed test events.
        event.setdefault("labels", {})["praxis_lab"] = "seed"
        for field, share in spec.sparse_fields.items():
            if rng.random() >= share:
                _drop(event, field)
        events.append(event)
    return sorted(events, key=lambda e: e["@timestamp"])


def seed(repo: ContentRepo, client: Client, now: datetime | None = None) -> dict[str, int]:
    """Top up every lab source from its newest event (or 14 days ago) to now.

    A source with `silent_for_days` stops that many days before now, which is
    how the lab models a log source that went quiet.
    """
    now = now or datetime.now(UTC)
    telemetry = repo.lab_telemetry.get(client.id)
    if telemetry is None:
        raise ValueError(f"{client.id} has no lab/telemetry.yml")
    written: dict[str, int] = {}
    for platform_name in client.platforms.enabled():
        platform = get_platform(platform_name)
        for spec in telemetry.sources:
            note = repo.datamap.get((platform_name, spec.source))
            if note is None:
                raise ValueError(f"no datamap-catalog note for {platform_name}/{spec.source}")
            start = now - WINDOW
            last = platform.last_seeded_event(client, spec.source)
            if last:
                start = max(start, datetime.fromisoformat(last.replace("Z", "+00:00")))
            end = now - timedelta(days=spec.silent_for_days)
            events = generate(client, spec, note.sample, start, end)
            written[spec.source] = platform.write_telemetry(client, spec.source, events)
    return written
