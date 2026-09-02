"""Phase 13 diagnostic: is each attack chain held together by real cross-entity
overlap, or by a single shared host (a proxy / jump box)?  Run it against
accumulating live data; a chain flagged `!!` deserves a look before you trust it.

    python -m scripts.chain_quality
"""
from __future__ import annotations

from app.attack_chain.stitcher import chain_quality


def main() -> None:
    rows = chain_quality()
    if not rows:
        print("no chains yet")
        return
    flagged = 0
    for r in rows:
        mark = "!!" if r["flag"] != "ok" else "  "
        print(f"{mark} chain {r['chain_id']}  {r['stages']} stages  {r['title']}")
        for n, shared in enumerate(r["links"]):
            print(f"     stage {n} -> {n + 1}: {', '.join(shared) or '(no direct overlap)'}")
        flagged += r["flag"] != "ok"
    print(f"\n{len(rows)} chain(s); {flagged} flagged "
          "(hub-host = one shared host across every stage; weak-link = adjacent "
          "stages share nothing directly). Verify these are real chains.")


if __name__ == "__main__":
    main()
