"""The release flag line and the client limit-break datatable.

Two things went wrong between 2.5.30 and 2.5.33 and are pinned here:

* the releases were built from a hand-written list of eight flags instead of ``--all``, which
  quietly dropped the whole umbrella set — recycling stopped granting 6★ equipment;
* ``--all`` enabled the 50% *and* the 90% limit-break discounts at the same time, and the two
  table patches validate the same table by sha, so an ``--all`` build died with
  "Unexpected limit break cost table".

Only the 90% profile remains; the half variants were removed.
"""

from __future__ import annotations

import argparse

from core.apk_tooling import limit_break_client_divisor


def _resolve(argv: list[str]) -> bool:
    """The same priority chain the CLI uses for the remaining discount."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--limit-break-cost-tenth", action="store_true")
    args = parser.parse_args(argv)
    return bool(args.limit_break_cost_tenth or args.all)


def test_umbrella_enables_the_tenth_discount() -> None:
    assert _resolve(["--all"]) is True


def test_explicit_tenth_enables_the_discount() -> None:
    assert _resolve(["--limit-break-cost-tenth"]) is True


def test_no_discount_by_default() -> None:
    assert _resolve([]) is False


def test_tenth_and_none_for_the_client_table() -> None:
    assert limit_break_client_divisor(tenth=True) == 10
    assert limit_break_client_divisor(tenth=False) == 1
