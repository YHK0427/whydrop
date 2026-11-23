"""Rollups, retention and the disk guard (spec §7). Runs every 10 minutes on the store's thread."""
import logging
import shutil

log = logging.getLogger(__name__)

DAY_MS = 86_400_000
KEEP_1S_MS = 7 * DAY_MS
KEEP_INCIDENT_MS = 90 * DAY_MS
INCIDENT_PAD_MS = 10 * 60_000
GB = 2**30
ROLLUP_LAG_MS = 5 * 60_000   # late replies still update 1 s rows for a few seconds: roll up well behind them

# a minute is computed whole from its seconds, so rolling it again (after a clock step back) is safe
_ROLLUP = """
INSERT OR REPLACE INTO samples_1m (agent_id, ts_ms, probe, pair, sent, ok, lost, lost_up, lost_down, lost_dir_unknown, late,
                        local_fail, rtt_min, rtt_avg, rtt_max, rtt_p95, extra_json)
SELECT agent_id, (ts_ms / 60000) * 60000, probe, pair, SUM(sent), SUM(ok), SUM(lost), SUM(lost_up), SUM(lost_down),
       SUM(lost_dir_unknown), SUM(late), SUM(local_fail), MIN(rtt_min),
       SUM(rtt_avg * ok) / NULLIF(SUM(CASE WHEN rtt_avg IS NOT NULL THEN ok END), 0), MAX(rtt_max), MAX(rtt_p95), NULL
FROM samples_1s WHERE agent_id = ? AND ts_ms >= ? AND ts_ms < ?
GROUP BY agent_id, (ts_ms / 60000) * 60000, probe, pair
"""

# 1 s rows older than 7 days go, unless they sit within ±10 min of an incident that is under 90 days old
_DELETE_CHUNK = """
DELETE FROM samples_1s WHERE (agent_id, ts_ms, probe, pair) IN (
  SELECT s.agent_id, s.ts_ms, s.probe, s.pair FROM samples_1s s
  WHERE s.agent_id = ? AND s.ts_ms < ? AND (s.ts_ms < ? OR NOT EXISTS (
    SELECT 1 FROM incidents i WHERE i.agent_id = s.agent_id AND i.start_ms >= ?
      AND s.ts_ms >= i.start_ms - ? AND s.ts_ms < COALESCE(i.end_ms, i.start_ms) + ?))
  LIMIT ?)
"""


def _disk_usage(path) -> tuple[int, int]:
    u = shutil.disk_usage(path)
    return u.free, u.total


async def housekeep(store, now_ms: int, *, free_bytes=None, min_free_mb: int | None = None, chunk: int = 5000) -> dict:
    free, total = (free_bytes or (lambda: _disk_usage(store.path.parent)))()
    threshold = min_free_mb * 2**20 if min_free_mb is not None else min(2 * GB, int(total * 0.05))
    disk_full = free < threshold
    if disk_full != store.paused:
        (log.error if disk_full else log.info)("disk guard: %s (free %.1f GB)", "writes stopped" if disk_full
                                                else "writes resumed", free / GB)
    store.paused = disk_full
    await store.meta_set("disk_full", "1" if disk_full else "0")

    await store.flush()
    cutoff_1s = (now_ms - KEEP_1S_MS) // 60_000 * 60_000
    roll_to = (now_ms - ROLLUP_LAG_MS) // 60_000 * 60_000   # minute rows trail the 1 s rows by minutes, not a week
    first = await store.execute("SELECT MIN(ts_ms) FROM samples_1s WHERE agent_id = ?", (store.agent_id,))
    start = first[0][0] // 60_000 * 60_000 if first and first[0][0] is not None else roll_to
    done = int(await store.meta_get("rollup_until") or 0)
    if done > roll_to:   # the clock stepped back (a Pi without RTC rebooting offline): seconds land behind the point
        run = await store.execute("SELECT start_ms FROM agent_runs WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
                                  (store.agent_id,))
        began = min(run[0][0] if run else roll_to, roll_to) // 60_000 * 60_000 - 60_000   # this run wrote nothing earlier
        done = max(began, done - KEEP_1S_MS + DAY_MS)   # below that, seconds are gone: recomputing would lose minutes
        await store.meta_set("rollup_until", str(done))
    since = max(done, start)   # skip empty hours
    while since < roll_to:   # an hour per statement: a first run over a week of rows doesn't hold the store for long
        stop = min(since + 3_600_000, roll_to)
        await store.execute_atomic([(_ROLLUP, (store.agent_id, since, stop)),   # a crash can't roll an hour up twice
                                    ("INSERT OR REPLACE INTO meta (key, value) VALUES ('rollup_until', ?)", (str(stop),))])
        since = stop
    if not await store.meta_get("rollup_until"):
        await store.meta_set("rollup_until", str(roll_to))
    deleted, chunks = 0, 0
    while True:
        n = await store.execute_rowcount(_DELETE_CHUNK, (store.agent_id, cutoff_1s, now_ms - KEEP_INCIDENT_MS,
                                                         now_ms - KEEP_INCIDENT_MS, INCIDENT_PAD_MS, INCIDENT_PAD_MS,
                                                         chunk))
        if not n:
            break
        deleted += n
        chunks += 1
    return {"disk_full": disk_full, "deleted_1s": deleted, "chunks": chunks}
