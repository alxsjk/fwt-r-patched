# Known Bugs

This document tracks reproducible, unresolved issues in FWT Reborn Patch
builds. Each entry lists the affected versions, the observed behavior, the
evidence gathered so far, and the recommended workaround until a fix ships.

## KB-001 — Mythical Stones do not reappear after restarting the game

- **Status:** Open (pending resolution; no code fix ships in `2.5.53`)
- **Affected versions:** `2.5.51` – `2.5.53`
- **Feature:** [02.07 Mythical Stone in Event Shop](FEATURE_CATALOG.md)
  (`--mythical-stone-shop`, included in `--all`)
- **Summary:** Mythical Stones (`item_code 2040031`) purchased from the
  Special Product offer (`2330278`) are charged, delivered, and fully usable
  in the same session, but the general inventory screen and the costume
  enchant screen show **zero** after closing and reopening the game.

### Workaround

Use the stones in the same session in which you buy them. Within one session
the client tracks them correctly: costume enchant consumes five stones plus
manastone, advances `enchant_cnt`, and the running count is visible on both
screens. When you want to enchant in a later session, buy at least five
stones first — the server stacks the new purchase onto the persisted total,
and the display picks the count back up from the purchase response.

Nothing is lost across restarts: the server keeps every purchased stone in
the save file and serves it at every login; only the client display resets
to zero until the next in-session purchase or enchant.

### Evidence (device validation on the `2.5.53` build)

- **Server persistence works.** The save contains
  `{"item_idx": 68, "item_code": "2040031", "item_count": N}`;
  `shop_buy_counts["2330278"]` grows with each purchase, the same slot
  stacks across sessions, and event coins are charged correctly.
- **The login sync serves the item.** `GET_MY_ITEM_INFO` returns all
  inventory rows — including the stone row with the correct count — in every
  captured restart.
- **In-session responses update the client.** `SHOP_BUY_CONTENTS` returns the
  full updated slot (`items`) and `COSTUME_ENCHANT` returns the deducted slot
  (`item_list`) plus the updated costume record; the inventory and the
  enchant counter reflect both immediately.
- **The original game ships the stone as a server inventory item.** The
  default inventory template embedded in `libfwt_local_server.so` grants
  `2040031 x200000` at an early slot.

### Ruled out

- **Server load/persistence/stacking:** verified with save diffs and login
  captures across three restarts.
- **Served payload omission:** the stone row is present in every login
  response payload.
- **Client item registry membership:** rewriting the slot to the registered
  costume material `33816625` (present in `item.unity3d` and
  `itemtype.unity3d` with icon, names, and type) still displays zero, so the
  client drops the served row regardless of registry membership.
- **Slot position and corrupted template rows:** moving the stone to an
  early `item_idx` and removing the corrupted hex-written template rows
  (`1D4C3`, `C`, `13000Y`) from the inventory did not restore the display.

### Suspected area and next lead

The client's `GET_MY_ITEM_INFO` ingestion path discards the stone row (or the
counter it feeds), while the shop and enchant response handlers update that
counter directly. The next reverse-engineering lead is the
`CostumeEnchantPopup` / `EnchantCostumeItem` client path in `libil2cpp.so`
and `global-metadata.dat`: locate the `GET_MY_ITEM_INFO` handler, compare it
with the `SHOP_BUY_CONTENTS` / `COSTUME_ENCHANT` handlers, and find which
in-memory counter the enchant UI reads at scene load.
