## Summary

- What changed:
- Why:

## Related Issue

<!-- Required for external PRs: reference an OPEN issue carrying the 'approved' label from @alxsjk (e.g., Closes #123). -->
Closes #

## Verification

Run inside the project virtualenv before requesting review:

- [ ] `python -m compileall -q core gui tools tests fwt_patcher.py`
- [ ] `ruff check .`
- [ ] `mypy core gui fwt_patcher.py tools tests`
- [ ] `pytest -q -m "not integration"`
- [ ] Updated `docs/FEATURE_CATALOG.md`, `gui/feature_catalog.py`, `gui/main_window.py`, `core/patch_inspector.py`, and `tests/test_gui_feature_parity.py` (if patch options changed)

## Policy & Hygiene Checklist

- [ ] No copyrighted binaries (`*.apk`, `*.so`, `*.dex`, `*.dat`, `*.jar`) committed
- [ ] No secrets, AES cipher keys, signing keystores, saves, or `.env` files committed
- [ ] No personal emails, local user paths, private hostnames, or private LAN IPs included
- [ ] All code, comments, tests, documentation, and PR text are written in English
- [ ] Commits are focused and kept clean without unrelated refactors
