# evaders/xtest-coalesce — behavioral pressure-test for the coalesced-events terminus

Does **X11 XTEST** motion injection (no real hardware) defeat the coalesced-events tells
(`bh.synthetic_no_coalesced` / `br.coalesced_untrusted`)? The detector's coalesced ladder had been grounded
only against **CDP** dispatch (iter-60), which enters the input pipeline *downstream* of the browser's
coalescing stage. XTEST enters *upstream* (where real hardware does), so it was the untested path.

## Grounded result (2026-06-20)

```
XTEST_RESULT engine=chromium max_coalesced=0 any_untrusted=False pointermove_count=51
XTEST_RESULT engine=firefox  max_coalesced=0 any_untrusted=False pointermove_count=17
```

XTEST motion arrives **trusted** but **`max_coalesced=0`** on both engines: X11 **motion compression**
collapses the burst to one position per frame *before* the browser's coalescing stage, so
`getCoalescedEvents()` is empty. → XTEST still trips `bh.synthetic_no_coalesced` (coalescedMax ≤ 1).

The stronger path — a **uinput** kernel device (evdev) — is architecturally excluded under **Xvfb**: a
virtual X server has no evdev/libinput input driver, so a uinput mouse never reaches the browser. Producing
coalesced events needs **Xorg + libinput** reading a real (or uinput) high-rate device — a real-hardware-like
display stack, the exact terminus the ladder names.

## Conclusion

The coalesced terminus **holds**, now grounded against **three** software injection mechanisms (CDP / XTEST /
uinput-path) instead of one. No EVADES; no detector change. The residual remains a genuine
external/real-input-stack frontier. Run: `python /probe/probe.py` inside an Xvfb-capable Playwright image.
