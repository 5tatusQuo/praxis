"""Platform-neutral operations shared by the CLI, the API and CI."""

from __future__ import annotations

import subprocess
from pathlib import Path

from praxis import attack
from praxis.content.docs import lint_readme, section
from praxis.content.loader import ContentRepo, DetectionBundle, Issue
from praxis.content.models import Client
from praxis.platforms import RenderedRule, get_platform, implementation_files
from praxis.settings import get_settings

# Lifecycle states that are deployed. Drafts and deprecated rules are not.
DEPLOYED_LIFECYCLES = ("staged", "production")


def load_repo(root: Path | None = None) -> ContentRepo:
    return ContentRepo(root or get_settings().content_dir, implementation_files())


def validate(repo: ContentRepo) -> list[Issue]:
    """Schema, references, ATT&CK ids, README template and per-platform checks."""
    issues = list(repo.issues)
    for bundle in repo.detections.values():
        meta_path = bundle.path / "detection.yml"
        for ref in bundle.meta.attack:
            if not attack.is_technique(ref.technique):
                issues.append(Issue(meta_path, f"{ref.technique} is not in ATT&CK"))
            elif not attack.is_tactic(ref.tactic):
                issues.append(Issue(meta_path, f"{ref.tactic} is not an ATT&CK tactic"))
            elif ref.tactic not in attack.technique_tactics(ref.technique):
                issues.append(
                    Issue(meta_path, f"{ref.technique} does not belong to tactic {ref.tactic}")
                )
        known = set(attack.bundle()["data_components"])
        for component in bundle.meta.data_components:
            if component not in known:
                issues.append(Issue(meta_path, f"unknown ATT&CK data component {component!r}"))
        if bundle.readme:
            issues.extend(
                Issue(bundle.path / "README.md", p) for p in lint_readme(bundle.readme, bundle.id)
            )
        for platform_name, impl in bundle.implementations.items():
            if platform_name in bundle.meta.log_sources:
                issues.extend(
                    Issue(impl.path, p) for p in get_platform(platform_name).check(bundle)
                )
    for client in repo.clients.values():
        for bundle in repo.detections_for(client):
            if not any(p in bundle.implementations for p in client.platforms.enabled()):
                issues.append(
                    Issue(
                        repo.root / "clients" / client.id / "client.yml",
                        f"{bundle.id} has no implementation for this client's platforms",
                    )
                )
    return issues


def deployable(bundle: DetectionBundle) -> bool:
    return bundle.meta.lifecycle in DEPLOYED_LIFECYCLES


def render_client(repo: ContentRepo, client: Client, platform_name: str) -> list[RenderedRule]:
    """Every deployable rule for one client on one platform."""
    platform = get_platform(platform_name)
    return [
        platform.render(bundle, client)
        for bundle in repo.detections_for(client)
        if deployable(bundle) and platform_name in bundle.implementations
    ]


def _git(args: list[str], cwd: Path) -> str | None:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else None


def docs_follow_queries(repo: ContentRepo, base: str) -> list[Issue]:
    """A query change must come with a change to the README's 'How it works'."""
    issues = []
    top = _git(["rev-parse", "--show-toplevel"], repo.root)
    if top is None:
        return [Issue(repo.root, "not inside a git repository")]
    top_path = Path(top.strip())
    for bundle in repo.detections.values():
        old_readme = _git(
            ["show", f"{base}:{(bundle.path / 'README.md').relative_to(top_path)}"], top_path
        )
        if old_readme is None:
            continue  # new detection
        for impl in bundle.implementations.values():
            old_query = _git(["show", f"{base}:{impl.path.relative_to(top_path)}"], top_path)
            if old_query is None or old_query.strip() == impl.query:
                continue
            if section(old_readme, "How it works") == section(bundle.readme, "How it works"):
                issues.append(
                    Issue(
                        impl.path,
                        "query changed but README 'How it works' did not; update the docs",
                    )
                )
    return issues
