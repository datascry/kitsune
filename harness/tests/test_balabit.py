# harness/tests/test_balabit — parse Balabit CSV into trajectories and segment on pauses.
# Synthetic fixture in the real Balabit column format (the actual dataset is fetched at use-time).

from __future__ import annotations

from kitsune_harness.balabit import movement_segments, parse_balabit

# A few rows in the real Balabit format: record ts, client ts, button, state, x, y.
_CSV = """record timestamp,client timestamp,button,state,x,y
0.0,0.0,NoButton,Move,1043,410
0.23,0.09,NoButton,Move,1024,410
0.34,0.23,NoButton,Move,979,409
0.45,0.40,NoButton,Move,950,412
malformed,row,here
0.50,2.00,NoButton,Move,500,500
0.60,2.10,NoButton,Move,505,505
"""


def test_parse_balabit_uses_client_ts_and_skips_bad_rows() -> None:
    samples = parse_balabit(_CSV)
    assert len(samples) == 6  # header + malformed row dropped
    assert samples[0] == (1043.0, 410.0, 0.0)
    assert samples[2] == (979.0, 409.0, 0.23)


def test_movement_segments_split_on_pause() -> None:
    # The jump from t=0.40 to t=2.00 is a >0.5s pause → a segment boundary. With min_len=2, the first
    # run (4 points) is kept; the trailing 2-point run is dropped at the default min_len.
    samples = parse_balabit(_CSV)
    segs = movement_segments(samples, max_gap=0.5, min_len=2)
    assert len(segs) == 2 and len(segs[0]) == 4 and len(segs[1]) == 2
    assert movement_segments(samples, max_gap=0.5, min_len=8) == []  # nothing long enough


def test_empty_input() -> None:
    assert parse_balabit("") == []
    assert movement_segments([]) == []
