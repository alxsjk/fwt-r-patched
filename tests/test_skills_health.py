"""Health and governance tests for tracked project skills and Spec Kit artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SKILLS_ROOT = PROJECT_ROOT / ".agents" / "skills"
CONSTITUTION_PATH = PROJECT_ROOT / ".specify" / "memory" / "constitution.md"
AGENTS_PATH = PROJECT_ROOT / "AGENTS.md"
TASKS_OVERRIDE_PATH = (
    PROJECT_ROOT / ".specify" / "templates" / "overrides" / "tasks-template.md"
)

_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
_PATH_TOKEN_RE = re.compile(
    r"`((?:core|gui|tools|tests|docs|scripts|\.github|\.specify|\.agents)/[A-Za-z0-9_./*-]+)`"
)
_ROOT_FILE_TOKEN_RE = re.compile(
    r"`(fwt_patcher\.py|pyproject\.toml|requirements(?:-dev)?\.txt|README\.md|CHANGELOG\.md|CONTRIBUTING\.md)`"
)
_DISALLOWED_PII_PATTERNS = (
    re.compile(r"\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"(?i)C:\\Users\\"),
    re.compile(r"/home/[a-zA-Z0-9._-]+/"),
)


def _tracked_fwt_skill_files() -> list[Path]:
    return sorted(SKILLS_ROOT.glob("fwt-*/SKILL.md"))


def test_project_skills_frontmatter_layout_and_registration() -> None:
    skill_files = _tracked_fwt_skill_files()
    assert skill_files, "expected at least one tracked fwt-* skill under .agents/skills/"

    agents_text = AGENTS_PATH.read_text(encoding="utf-8")
    for skill_path in skill_files:
        raw = skill_path.read_bytes()
        assert b"\r\n" not in raw, f"{skill_path} must use LF line endings"
        text = raw.decode("utf-8")
        match = _FRONTMATTER_RE.match(text)
        assert match is not None, f"{skill_path} is missing YAML frontmatter"
        frontmatter = match.group(1)

        name_match = re.search(r"^name:\s*['\"]?([a-z0-9-]+)['\"]?\s*$", frontmatter, re.MULTILINE)
        assert name_match is not None, f"{skill_path} frontmatter missing valid 'name'"
        skill_name = name_match.group(1)
        assert skill_name == skill_path.parent.name, (
            f"{skill_path} frontmatter name {skill_name!r} != directory {skill_path.parent.name!r}"
        )
        assert re.search(r"^description:\s*\S+", frontmatter, re.MULTILINE), (
            f"{skill_path} frontmatter missing 'description'"
        )
        assert f"`{skill_name}`" in agents_text, (
            f"{skill_name} is not documented under Project Skills in AGENTS.md"
        )


def test_documented_repo_paths_in_skills_and_governance_exist() -> None:
    docs_to_check = [*_tracked_fwt_skill_files(), CONSTITUTION_PATH, AGENTS_PATH]
    # Local-only Spec Kit paths that do not exist on a fresh CI checkout.
    local_only_prefixes = (
        ".specify/scripts/",
        ".specify/integrations/",
        ".agents/skills/speckit-",
    )
    local_only_exact = {
        ".specify/templates/*.md",
    }

    missing: list[str] = []
    for doc in docs_to_check:
        text = doc.read_text(encoding="utf-8")
        for token in sorted(set(_PATH_TOKEN_RE.findall(text))):
            if token in local_only_exact or token.startswith(local_only_prefixes):
                continue
            if "*" in token:
                if not list(PROJECT_ROOT.glob(token)):
                    missing.append(f"{doc.relative_to(PROJECT_ROOT)}: empty glob `{token}`")
                continue
            if not (PROJECT_ROOT / token).exists():
                missing.append(f"{doc.relative_to(PROJECT_ROOT)}: missing `{token}`")
        for token in sorted(set(_ROOT_FILE_TOKEN_RE.findall(text))):
            if not (PROJECT_ROOT / token).exists():
                missing.append(f"{doc.relative_to(PROJECT_ROOT)}: missing `{token}`")

    assert not missing, "stale path references found:\n" + "\n".join(missing)


def test_verification_gates_exclude_both_integration_and_slow() -> None:
    files_with_gates = [
        CONSTITUTION_PATH,
        AGENTS_PATH,
        SKILLS_ROOT / "fwt-add-patch" / "SKILL.md",
        SKILLS_ROOT / "fwt-pre-release-audit" / "SKILL.md",
    ]
    for path in files_with_gates:
        text = path.read_text(encoding="utf-8")
        assert '-m "not integration and not slow"' in text, (
            f"{path.relative_to(PROJECT_ROOT)} must use '-m \"not integration and not slow\"'"
        )
        assert '-m "not integration"' not in text, (
            f"{path.relative_to(PROJECT_ROOT)} uses '-m \"not integration\"' without 'and not slow'"
        )


def test_governance_files_use_lf_and_contain_no_pii_or_lan_ips() -> None:
    gitattributes_text = (PROJECT_ROOT / ".gitattributes").read_text(encoding="utf-8")
    for entry in ("*.sh", "AGENTS.md", ".specify/**", ".agents/**"):
        assert f"{entry} text eol=lf" in gitattributes_text, (
            f".gitattributes must enforce 'text eol=lf' for {entry}"
        )

    tracked_files = [
        *_tracked_fwt_skill_files(),
        CONSTITUTION_PATH,
        AGENTS_PATH,
        TASKS_OVERRIDE_PATH,
    ]
    for path in tracked_files:
        raw = path.read_bytes()
        assert b"\r\n" not in raw, f"{path.relative_to(PROJECT_ROOT)} must use LF line endings"
        text = raw.decode("utf-8")
        for pattern in _DISALLOWED_PII_PATTERNS:
            match = pattern.search(text)
            assert match is None, (
                f"{path.relative_to(PROJECT_ROOT)} contains disallowed PII/LAN pattern: {match.group(0)!r}"
            )


def test_speckit_tasks_template_override_aligns_with_constitution() -> None:
    assert TASKS_OVERRIDE_PATH.is_file(), "missing Spec Kit tasks-template project override"
    text = TASKS_OVERRIDE_PATH.read_text(encoding="utf-8")
    assert "MANDATORY" in text
    assert "Tests are OPTIONAL" not in text
    assert "core/" in text
    assert "tests/" in text


def test_speckit_manifests_remain_unmodified_when_installed() -> None:
    manifest_dir = PROJECT_ROOT / ".specify" / "integrations"
    manifests = sorted(manifest_dir.glob("*.manifest.json")) if manifest_dir.is_dir() else []
    if not manifests:
        pytest.skip("local Spec Kit manifests are not installed in this checkout")

    mismatches: list[str] = []
    for manifest_path in manifests:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        files = data.get("files", {})
        assert isinstance(files, dict)
        for rel_path, expected_sha in files.items():
            target = PROJECT_ROOT / rel_path
            if not target.is_file():
                mismatches.append(f"{manifest_path.name}: missing {rel_path}")
                continue
            actual_sha = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual_sha != expected_sha:
                mismatches.append(f"{manifest_path.name}: checksum mismatch for {rel_path}")

    assert not mismatches, "Spec Kit manifest integrity violation:\n" + "\n".join(mismatches)


def test_speckit_template_resolver_selects_project_tasks_override() -> None:
    resolver = PROJECT_ROOT / ".specify" / "scripts" / "python" / "resolve_template.py"
    if not resolver.is_file():
        pytest.skip("local Spec Kit scripts are not installed in this checkout")

    proc = subprocess.run(
        [sys.executable, str(resolver), "tasks-template", "--json"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    content = payload["TEMPLATE_CONTENT"]
    assert "MANDATORY" in content
    assert "Tests are OPTIONAL" not in content
