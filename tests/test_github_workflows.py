"""Static and behavioral validation for GitHub authorial governance workflows."""

from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
GITHUB_DIR = PROJECT_ROOT / ".github"
WORKFLOWS_DIR = GITHUB_DIR / "workflows"


def _extract_embedded_python(workflow_path: Path) -> str:
    lines = workflow_path.read_text(encoding="utf-8").splitlines()
    start: int | None = None
    end: int | None = None
    for idx, line in enumerate(lines):
        if start is None and line.strip() == "python3 - <<'PY'":
            start = idx + 1
        elif start is not None and line.strip() == "PY":
            end = idx
            break
    assert start is not None, f"missing embedded python start in {workflow_path}"
    assert end is not None, f"missing embedded python end in {workflow_path}"
    return textwrap.dedent("\n".join(lines[start:end])) + "\n"


def _load_workflow_namespace(workflow_name: str) -> dict[str, Any]:
    path = WORKFLOWS_DIR / workflow_name
    source = _extract_embedded_python(path)
    ast.parse(source, filename=str(path))
    namespace: dict[str, Any] = {}
    exec(compile(source, str(path), "exec"), namespace)
    return namespace


def test_codeowners_and_issue_templates_enforce_authorial_policy() -> None:
    codeowners = (GITHUB_DIR / "CODEOWNERS").read_text(encoding="utf-8")
    assert "* @alxsjk" in codeowners

    config = (GITHUB_DIR / "ISSUE_TEMPLATE" / "config.yml").read_text(encoding="utf-8")
    assert "blank_issues_enabled: false" in config

    for template_name in ("bug_report.yml", "feature_request.yml"):
        text = (GITHUB_DIR / "ISSUE_TEMPLATE" / template_name).read_text(encoding="utf-8")
        assert '"needs-triage"' in text, f"{template_name} missing needs-triage default label"

    pr_template = (GITHUB_DIR / "PULL_REQUEST_TEMPLATE.md").read_text(encoding="utf-8")
    assert "approved" in pr_template


def test_all_workflows_declare_permissions_and_follow_fork_safety_invariants() -> None:
    workflows = sorted(WORKFLOWS_DIR.glob("*.yml"))
    assert {p.name for p in workflows} >= {
        "ci.yml",
        "pr-policy.yml",
        "pr-policy-comment.yml",
        "issue-triage.yml",
        "release.yml",
    }

    uses_pattern = re.compile(r"uses:\s*([^\s#]+)")
    for wf in workflows:
        text = wf.read_text(encoding="utf-8")
        assert re.search(r"(?m)^permissions:(?:\s*\{\}|\s*$)", text), f"{wf.name} must declare permissions:"
        for match in uses_pattern.finditer(text):
            ref = match.group(1)
            assert re.search(r"@[0-9a-f]{40}$", ref), f"{wf.name} must pin action by commit SHA: {ref}"
        if wf.name in {"pr-policy-comment.yml", "issue-triage.yml"}:
            assert "actions/checkout" not in text, f"{wf.name} must never checkout code"
        for run_block in re.split(r"(?m)^\s*run:\s*\|?\s*\n", text)[1:]:
            # Check indented script lines up to the next YAML step key.
            script_lines = []
            for line in run_block.splitlines():
                if line and not line.startswith(" " * 8):
                    break
                script_lines.append(line)
            script = "\n".join(script_lines)
            assert "${{" not in script, (
                f"{wf.name} must pass GitHub expressions through env:, not inline in run:"
            )

    pr_policy = (WORKFLOWS_DIR / "pr-policy.yml").read_text(encoding="utf-8")
    assert "pull_request:" in pr_policy
    assert "pull_request_target:" not in pr_policy
    assert "name: PR Policy (Approved Issue)" in pr_policy
    assert re.search(r"(?m)^    if:", pr_policy) is None


def test_pr_policy_evaluates_maintainer_and_linked_issue_states() -> None:
    ns_gate = _load_workflow_namespace("pr-policy.yml")
    ns_comment = _load_workflow_namespace("pr-policy-comment.yml")

    for ns in (ns_gate, ns_comment):
        extract = ns["extract_issue_numbers"]
        evaluate = ns["evaluate_pr_policy"]

        # Maintainer PR passes without an issue reference.
        ok, msg = evaluate("alxsjk", "", "alxsjk/fwt-r-patched", lambda _n: (404, None))
        assert ok is True
        assert "Maintainer" in msg

        # Trusted Dependabot PR passes policy without an approved issue.
        ok, msg = evaluate("dependabot[bot]", "", "alxsjk/fwt-r-patched", lambda _n: (404, None))
        assert ok is True
        assert "Dependabot" in msg

        # Template HTML comments are ignored.
        assert extract("<!-- Closes #123 -->\nSummary", "alxsjk/fwt-r-patched") == []
        ok, _ = evaluate("contributor", "<!-- Closes #123 -->", "alxsjk/fwt-r-patched", lambda _n: (404, None))
        assert ok is False

        # Full GitHub issue URLs and short #N references are both extracted cleanly.
        assert extract(
            "Fixes https://github.com/alxsjk/fwt-r-patched/issues/42 and (#7)",
            "alxsjk/fwt-r-patched",
        ) == [42, 7]

        # Non-existent issue fails.
        ok, msg = evaluate("contributor", "Closes #99", "alxsjk/fwt-r-patched", lambda _n: (404, None))
        assert ok is False
        assert "#99 not found" in msg

        # Linking another PR instead of an issue fails.
        ok, msg = evaluate(
            "contributor",
            "Closes #10",
            "alxsjk/fwt-r-patched",
            lambda _n: (200, {"state": "open", "pull_request": {}, "labels": [{"name": "approved"}]}),
        )
        assert ok is False
        assert "pull request" in msg

        # Closed issue fails even if it has the approved label.
        ok, msg = evaluate(
            "contributor",
            "Closes #11",
            "alxsjk/fwt-r-patched",
            lambda _n: (200, {"state": "closed", "labels": [{"name": "approved"}]}),
        )
        assert ok is False
        assert "closed" in msg

        # Open issue without the approved label fails.
        ok, msg = evaluate(
            "contributor",
            "Closes #12",
            "alxsjk/fwt-r-patched",
            lambda _n: (200, {"state": "open", "labels": [{"name": "needs-triage"}]}),
        )
        assert ok is False
        assert "approved" in msg

        # Open issue WITH the approved label passes.
        ok, msg = evaluate(
            "contributor",
            "Closes #13",
            "alxsjk/fwt-r-patched",
            lambda _n: (200, {"state": "open", "labels": [{"name": "approved"}]}),
        )
        assert ok is True
        assert "#13 verified" in msg


def test_pr_policy_comment_sync_creates_updates_and_acknowledges_resolution() -> None:
    ns = _load_workflow_namespace("pr-policy-comment.yml")
    sync = ns["sync_pr_comment"]
    marker = ns["MARKER"]

    calls: list[tuple[str, str, dict[str, Any] | None]] = []
    comments: list[dict[str, Any]] = []
    issue_state: dict[str, Any] = {"state": "open", "labels": [{"name": "needs-triage"}]}

    def fake_api(method: str, path: str, payload: dict[str, Any] | None) -> tuple[int, Any]:
        calls.append((method, path, payload))
        if method == "GET" and path.endswith("/issues/5"):
            return 200, issue_state
        if method == "GET" and "/issues/20/comments" in path:
            return 200, list(comments)
        if method == "POST" and path.endswith("/issues/20/comments"):
            assert payload is not None
            comments.append({"id": 777, "body": payload["body"]})
            return 201, comments[-1]
        if method == "PATCH" and path.endswith("/issues/comments/777"):
            assert payload is not None
            comments[0]["body"] = payload["body"]
            return 200, comments[0]
        return 404, None

    # First run with unapproved issue posts one comment with marker.
    sync("alxsjk/fwt-r-patched", 20, "alice", "Closes #5", fake_api)
    assert len(comments) == 1
    assert marker in comments[0]["body"]
    assert "PR Policy (Approved Issue)" in comments[0]["body"]

    # Second run updates existing comment instead of creating a duplicate.
    sync("alxsjk/fwt-r-patched", 20, "alice", "Closes #5", fake_api)
    assert len(comments) == 1
    assert any(m == "PATCH" for m, _, _ in calls)

    # Once maintainer approves issue #5, existing gate comment is updated to passing status.
    calls.clear()
    issue_state["labels"] = [{"name": "approved"}]
    sync("alxsjk/fwt-r-patched", 20, "alice", "Closes #5", fake_api)
    assert len(comments) == 1
    assert "policy check passed" in comments[0]["body"]

    # Clean PR with no prior gate comment stays noise-free.
    comments.clear()
    calls.clear()
    sync("alxsjk/fwt-r-patched", 20, "alice", "Closes #5", fake_api)
    assert comments == []
    assert not any(m in {"POST", "PATCH"} for m, _, _ in calls)


def test_issue_triage_adds_needs_triage_label_and_single_comment() -> None:
    ns = _load_workflow_namespace("issue-triage.yml")
    triage = ns["triage_issue"]
    marker = ns["MARKER"]

    labels: list[dict[str, str]] = [{"name": "bug"}]
    comments: list[dict[str, Any]] = []

    def fake_api(method: str, path: str, payload: dict[str, Any] | None) -> tuple[int, Any]:
        if method == "GET" and path.endswith("/issues/9"):
            return 200, {"labels": labels}
        if method == "POST" and path.endswith("/issues/9/labels"):
            assert payload is not None
            labels.extend({"name": lbl} for lbl in payload["labels"])
            return 200, labels
        if method == "GET" and "/issues/9/comments" in path:
            return 200, list(comments)
        if method == "POST" and path.endswith("/issues/9/comments"):
            assert payload is not None
            comments.append({"id": 888, "body": payload["body"]})
            return 201, comments[-1]
        return 404, None

    triage("alxsjk/fwt-r-patched", 9, "bob", fake_api)
    assert [lbl["name"] for lbl in labels] == ["bug", "needs-triage"]
    assert len(comments) == 1
    assert marker in comments[0]["body"]
    assert "@bob" in comments[0]["body"]
    assert "approved" in comments[0]["body"]

    # Running again must not duplicate the label or comment.
    triage("alxsjk/fwt-r-patched", 9, "bob", fake_api)
    assert [lbl["name"] for lbl in labels] == ["bug", "needs-triage"]
    assert len(comments) == 1
