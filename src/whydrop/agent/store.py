"""SQLite storage (spec §7): WAL, ordered migrations, batched writes on one dedicated thread."""
import asyncio
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import astuple, dataclass, fields
from pathlib import Path

from whydrop.agent.events import Event

_SAMPLE_COLS = ("ts_ms, probe, pair, sent, ok, lost, lost_up, lost_down, lost_dir_unknown, late, local_fail, "
                "rtt_min, rtt_avg, rtt_max, rtt_p95, extra_json")
_SAMPLE_DDL = ("agent_id INTEGER NOT NULL, ts_ms INTEGER NOT NULL, probe TEXT NOT NULL, pair TEXT NOT NULL, "
               "sent INTEGER, ok INTEGER, lost INTEGER, lost_up INTEGER DEFAULT 0, lost_down INTEGER DEFAULT 0, "
               "lost_dir_unknown INTEGER DEFAULT 0, late INTEGER DEFAULT 0, local_fail INTEGER DEFAULT 0, "
               "rtt_min REAL, rtt_avg REAL, rtt_max REAL, rtt_p95 REAL, extra_json TEXT, "
               "PRIMARY KEY (agent_id, ts_ms, probe, pair)")

MIGRATIONS: list[str] = [
    f"""
    CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
    CREATE TABLE samples_1s ({_SAMPLE_DDL}) WITHOUT ROWID;
    CREATE TABLE samples_1m ({_SAMPLE_DDL}) WITHOUT ROWID;
    CREATE TABLE udp_seq_ring (agent_id INTEGER NOT NULL, ts_ms INTEGER NOT NULL, seq INTEGER NOT NULL,
        echoed INTEGER, dir TEXT, PRIMARY KEY (agent_id, ts_ms, seq)) WITHOUT ROWID;
    CREATE TABLE segments (agent_id INTEGER NOT NULL, ts_ms INTEGER NOT NULL, segment TEXT NOT NULL,
        state TEXT NOT NULL, detail_json TEXT);
    CREATE INDEX segments_ts ON segments (agent_id, ts_ms);
    CREATE TABLE events (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, ts_ms INTEGER NOT NULL,
        kind TEXT NOT NULL, pair TEXT, detail_json TEXT);
    CREATE INDEX events_ts ON events (agent_id, ts_ms);
    CREATE TABLE incidents (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, start_ms INTEGER NOT NULL,
        end_ms INTEGER, primary_cause TEXT, cause_final TEXT, cause_changed INTEGER DEFAULT 0,
        tags_json TEXT, evidence_json TEXT);
    CREATE INDEX incidents_start ON incidents (agent_id, start_ms);
    CREATE TABLE conditions (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, kind TEXT NOT NULL,
        start_ms INTEGER NOT NULL, end_ms INTEGER, detail_json TEXT);
    CREATE TABLE selfcheck (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, ts_ms INTEGER NOT NULL,
        result_json TEXT);
    CREATE TABLE findings (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, kind TEXT NOT NULL,
        start_ms INTEGER NOT NULL, end_ms INTEGER, detail_json TEXT);
    CREATE TABLE nat_runs (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, start_ms INTEGER NOT NULL,
        end_ms INTEGER, status TEXT, detail_json TEXT);
    CREATE TABLE nat_results (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, run_id INTEGER NOT NULL,
        proto TEXT NOT NULL, delay_s INTEGER NOT NULL, alive INTEGER, detail_json TEXT);
    CREATE TABLE annotations (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, start_ms INTEGER NOT NULL,
        end_ms INTEGER, label TEXT NOT NULL, note TEXT);
    CREATE TABLE agent_runs (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, start_ms INTEGER NOT NULL,
        heartbeat_ms INTEGER, stop_ms INTEGER, version TEXT, tags_json TEXT);
    """,
]
# A second written twice (a result that arrived after its bucket was flushed) is merged, never replaced.
_UPSERT = (f"INSERT INTO samples_1s (agent_id, {_SAMPLE_COLS}) VALUES ({', '.join('?' * 17)}) "
           "ON CONFLICT (agent_id, ts_ms, probe, pair) DO UPDATE SET "
           "rtt_avg = CASE WHEN ok + excluded.ok = 0 THEN NULL ELSE "
           "(COALESCE(rtt_avg, 0) * ok + COALESCE(excluded.rtt_avg, 0) * excluded.ok) / (ok + excluded.ok) END, "
           "sent = sent + excluded.sent, ok = ok + excluded.ok, lost = lost + excluded.lost, "
           "lost_up = lost_up + excluded.lost_up, lost_down = lost_down + excluded.lost_down, "
           "lost_dir_unknown = lost_dir_unknown + excluded.lost_dir_unknown, late = late + excluded.late, "
           "local_fail = local_fail + excluded.local_fail, "
           "rtt_min = MIN(COALESCE(rtt_min, excluded.rtt_min), COALESCE(excluded.rtt_min, rtt_min)), "
           "rtt_max = MAX(COALESCE(rtt_max, excluded.rtt_max), COALESCE(excluded.rtt_max, rtt_max)), "
           "rtt_p95 = MAX(COALESCE(rtt_p95, excluded.rtt_p95), COALESCE(excluded.rtt_p95, rtt_p95)), "
           "extra_json = COALESCE(excluded.extra_json, extra_json)")
MAX_BUFFERED = 30_000
_INSERTABLE = {"segments", "incidents", "conditions", "selfcheck", "findings", "nat_runs", "nat_results",
               "annotations", "udp_seq_ring"}


@dataclass
class SampleRow:
    ts_ms: int
    probe: str
    pair: str
    sent: int
    ok: int
    lost: int
    lost_up: int = 0
    lost_down: int = 0
    lost_dir_unknown: int = 0
    late: int = 0
    local_fail: int = 0
    rtt_min: float | None = None
    rtt_avg: float | None = None
    rtt_max: float | None = None
    rtt_p95: float | None = None
    extra_json: str | None = None


assert ", ".join(f.name for f in fields(SampleRow)) == _SAMPLE_COLS


class Store:
    def __init__(self, path: Path, agent_id: int = 1):
        self.listeners: list = []   # (rows, events) callbacks: the live analysis reads what is recorded
        self.late_listeners: list = []  # (ts, probe, pair, direction) for rows already flushed
        self._path = Path(path)
        self.agent_id = agent_id
        self.paused = False  # disk guard: when True, buffered rows are dropped instead of written
        self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="whydrop-db")  # one connection, one thread
        self._con: sqlite3.Connection | None = None
        self._samples: list[SampleRow] = []
        self._events: list[Event] = []

    async def _db(self, fn, *args):
        return await asyncio.get_running_loop().run_in_executor(self._pool, fn, *args)

    def _open_sync(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self._path, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        version = con.execute("PRAGMA user_version").fetchone()[0]
        for i, sql in enumerate(MIGRATIONS[version:], start=version + 1):
            con.executescript(f"BEGIN;\n{sql}\nPRAGMA user_version = {i};\nCOMMIT;")  # tables + version, atomically
        self._con = con

    async def open(self) -> None:
        await self._db(self._open_sync)

    async def add_samples(self, rows: list[SampleRow]) -> None:
        self._samples.extend(rows)
        for fn in self.listeners:
            fn(rows, [])

    async def add_events(self, events: list[Event]) -> None:
        self._events.extend(events)
        for fn in self.listeners:
            fn([], events)

    def add_events_nowait(self, events: list[Event]) -> None:
        """For sync callbacks (canary/stream events): buffered like add_events, flushed with the next commit."""
        self._events.extend(events)
        for fn in self.listeners:
            fn([], events)

    def _flush_sync(self, samples: list[SampleRow], events: list[Event]) -> None:
        with self._con:
            self._con.executemany(_UPSERT, [(self.agent_id, *astuple(r)) for r in samples])
            self._con.executemany(
                "INSERT INTO events (agent_id, ts_ms, kind, pair, detail_json) VALUES (?, ?, ?, ?, ?)",
                [(self.agent_id, e.ts_ms, e.kind, e.pair, json.dumps(e.detail, ensure_ascii=False)) for e in events])

    @property
    def path(self) -> Path:
        return self._path

    async def flush(self) -> None:
        samples, events = self._samples, self._events
        self._samples, self._events = [], []
        if not (samples or events) or self.paused:
            return  # disk full: drop rather than fill the disk (spec §7 disk guard)
        try:
            await self._db(self._flush_sync, samples, events)
        except sqlite3.Error:
            # retry next flush, but never hold more than ~10 minutes of rows (128 MB container limit)
            self._samples = (samples + self._samples)[-MAX_BUFFERED:]
            self._events = (events + self._events)[-MAX_BUFFERED:]
            raise

    async def late(self, ts_ms: int, probe: str, pair: str) -> None:
        r = next((x for x in reversed(self._samples) if (x.ts_ms, x.probe, x.pair) == (ts_ms, probe, pair)
                  and x.lost > 0), None)   # a late reply turns a loss into "late": find the part of the second that has it
        if r is not None:
            r.late += 1
            r.lost -= 1
            return
        for fn in self.late_listeners:
            fn(ts_ms, probe, pair, None)

        def upd():
            with self._con:
                self._con.execute("UPDATE samples_1s SET late = late + 1, lost = lost - 1 "
                                  "WHERE agent_id=? AND ts_ms=? AND probe=? AND pair=? AND lost > 0",
                                  (self.agent_id, ts_ms, probe, pair))
        await self._db(upd)

    async def late_dir(self, ts_ms: int, probe: str, pair: str, direction: str) -> None:
        """A late reply for a send already counted as lost in `direction` (up | down | unknown)."""
        col = {"up": "lost_up", "down": "lost_down"}.get(direction, "lost_dir_unknown")
        r = next((x for x in reversed(self._samples) if (x.ts_ms, x.probe, x.pair) == (ts_ms, probe, pair)
                  and x.lost > 0), None)   # else it's in the DB, or a duplicate (the UPDATE needs lost > 0 too)
        if r is not None:
            r.late += 1
            r.lost -= 1
            setattr(r, col, max(0, getattr(r, col) - 1))
            return
        for fn in self.late_listeners:
            fn(ts_ms, probe, pair, direction)
        await self.execute(f"UPDATE samples_1s SET late = late + 1, lost = lost - 1, {col} = MAX(0, {col} - 1) "
                           "WHERE agent_id=? AND ts_ms=? AND probe=? AND pair=? AND lost > 0", (self.agent_id, ts_ms, probe, pair))

    async def insert(self, table: str, **cols) -> int:
        if table not in _INSERTABLE or not all(c.isidentifier() for c in cols):
            raise ValueError(f"not an insertable table: {table}")
        names = ", ".join(["agent_id", *cols])

        def ins():
            with self._con:
                cur = self._con.execute(f"INSERT INTO {table} ({names}) VALUES ({', '.join('?' * (len(cols) + 1))})",
                                        (self.agent_id, *cols.values()))
                return cur.lastrowid
        return await self._db(ins)

    async def execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        """Read or small write helper for later plans and housekeeping."""
        def ex():
            with self._con:
                return self._con.execute(sql, params).fetchall()
        return await self._db(ex)

    async def executemany(self, sql: str, rows: list[tuple]) -> None:
        def ex():
            with self._con:
                self._con.executemany(sql, rows)
        await self._db(ex)

    async def execute_rowcount(self, sql: str, params: tuple = ()) -> int:
        def ex():
            with self._con:
                return self._con.execute(sql, params).rowcount
        return await self._db(ex)

    async def execute_atomic(self, statements: list[tuple[str, tuple]]) -> None:
        """Several writes in one transaction: all of them land, or none."""
        def ex():
            with self._con:
                for sql, params in statements:
                    self._con.execute(sql, params)
        await self._db(ex)

    async def meta_get(self, key: str) -> str | None:
        rows = await self.execute("SELECT value FROM meta WHERE key=?", (key,))
        return rows[0][0] if rows else None

    async def meta_set(self, key: str, value: str) -> None:
        await self.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    async def run_start(self, ts_ms: int, version: str, tags: dict) -> int:
        rows = await self.execute("INSERT INTO agent_runs (agent_id, start_ms, heartbeat_ms, version, tags_json) "
                                  "VALUES (?, ?, ?, ?, ?) RETURNING id",
                                  (self.agent_id, ts_ms, ts_ms, version, json.dumps(tags)))
        return rows[0][0]

    async def run_heartbeat(self, run_id: int, ts_ms: int) -> None:
        await self.execute("UPDATE agent_runs SET heartbeat_ms=? WHERE id=?", (ts_ms, run_id))

    async def run_stop(self, run_id: int, ts_ms: int) -> None:
        await self.execute("UPDATE agent_runs SET stop_ms=? WHERE id=?", (ts_ms, run_id))

    async def close(self) -> None:
        try:
            if self._con is not None:
                try:
                    await self.flush()
                finally:
                    await self._db(self._con.close)
                    self._con = None
        finally:
            self._pool.shutdown(wait=True)
