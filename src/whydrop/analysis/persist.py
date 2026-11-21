"""Writes engine changes to the segments / conditions / incidents / findings tables (spec §7)."""
import json

from whydrop.analysis.incidents import Incident


def _tags(inc: Incident) -> str:
    return json.dumps({"tags": sorted(inc.tags), "segments": sorted(inc.segments), "chain": inc.chain,
                       "point": inc.point})


def _evidence(inc: Incident, cause) -> str:
    ev = dict(inc.evidence)
    if cause is not None:
        ev.update(cause=cause.rule, label=cause.label, next_step=cause.next_step, secondary=cause.secondary,
                  **{f"cause_{k}": v for k, v in cause.evidence.items()})
    ev["events"] = sorted({e.kind for e in inc.events})
    return json.dumps(ev, ensure_ascii=False, default=str)


class Recorder:
    def __init__(self, store, on_incident=None):
        self.store = store
        self.rows: dict[int, int] = {}          # incident key → incidents.id
        self._conds: dict[str, int] = {}
        self._findings: set[str] = set()
        self.on_incident = on_incident or (lambda op, inc: None)

    async def close_previous_run(self, run_id: int | None) -> None:
        """Incidents and conditions a previous run left open end at its last heartbeat, tagged agent_restarted,
        keeping the cause they had (spec §6.3); causes that never settled are frozen as they were."""
        aid = self.store.agent_id
        prev = await self.store.execute("SELECT MAX(COALESCE(stop_ms, heartbeat_ms, start_ms)) FROM agent_runs "
                                        "WHERE agent_id = ? AND id != ?", (aid, run_id if run_id is not None else -1))
        end = prev[0][0] if prev and prev[0][0] is not None else None
        for rid, start, tags in await self.store.execute(
                "SELECT id, start_ms, tags_json FROM incidents WHERE agent_id = ? AND end_ms IS NULL", (aid,)):
            t = json.loads(tags or "{}")
            t["tags"] = sorted(set(t.get("tags", [])) | {"agent_restarted"})
            await self.store.execute("UPDATE incidents SET end_ms = ?, tags_json = ?, cause_final = primary_cause "
                                     "WHERE id = ?", (max(start, end or start), json.dumps(t), rid))
        await self.store.execute("UPDATE incidents SET cause_final = primary_cause WHERE agent_id = ? AND "
                                 "end_ms IS NOT NULL AND cause_final IS NULL", (aid,))
        await self.store.execute("UPDATE conditions SET end_ms = MAX(start_ms, ?) WHERE agent_id = ? AND end_ms IS NULL",
                                 (end or 0, aid))

    async def nat_tcp_lower(self) -> int | None:
        """Longest TCP idle delay the last nat-test saw survive (R5 expiry vs loss)."""
        rows = await self.store.execute("SELECT detail_json FROM nat_runs WHERE agent_id = ? ORDER BY id DESC LIMIT 1",
                                        (self.store.agent_id,))
        if not rows:
            return None
        lo = (json.loads(rows[0][0] or "{}").get("tcp_range") or [None])[0]
        return int(lo) if lo is not None else None

    async def load_open(self) -> list[Incident]:
        """Incidents a previous run left open: the engine closes them, tagged agent_restarted (spec §6.3)."""
        rows = await self.store.execute("SELECT id, start_ms, tags_json FROM incidents WHERE agent_id = ? AND end_ms IS NULL",
                                        (self.store.agent_id,))
        out = []
        for rid, start, tags in rows:
            t = json.loads(tags or "{}")
            inc = Incident(start_ms=start, segments=set(t.get("segments", [])), tags=set(t.get("tags", [])),
                           chain=t.get("chain", []), point=t.get("point"))
            self.rows[inc.key] = rid
            out.append(inc)
        return out

    async def write(self, changes) -> None:
        for ch in changes:
            if ch.type == "segment":
                c = ch.obj
                await self.store.insert("segments", ts_ms=c.t_ms, segment=c.segment, state=c.state,
                                        detail_json=json.dumps(c.detail))
            elif ch.type == "condition":
                c = ch.obj
                if c.phase == "start":
                    d = dict(c.detail, **({"cause": ch.cause.rule, "label": ch.cause.label} if ch.cause else {}))
                    self._conds[c.kind] = await self.store.insert("conditions", kind=c.kind, start_ms=c.t_ms,
                                                                  detail_json=json.dumps(d))
                elif c.kind in self._conds:
                    await self.store.execute("UPDATE conditions SET end_ms = ? WHERE id = ?", (c.t_ms, self._conds.pop(c.kind)))
            elif ch.type == "finding":
                if ch.obj.kind not in self._findings:  # a standing finding: once, not once per repeat
                    self._findings.add(ch.obj.kind)
                    await self.store.insert("findings", kind=ch.obj.kind, start_ms=ch.obj.ts_ms or 0, detail_json="{}")
            elif ch.type == "incident":
                inc, op = ch.obj.incident, ch.obj.op
                rid = self.rows.get(inc.key)
                if rid is None:
                    self.rows[inc.key] = await self.store.insert(
                        "incidents", start_ms=inc.start_ms, end_ms=inc.end_ms, primary_cause=ch.cause.rule,
                        tags_json=_tags(inc), evidence_json=_evidence(inc, ch.cause))
                else:
                    await self.store.execute("UPDATE incidents SET start_ms=?, end_ms=?, primary_cause=?, tags_json=?, "
                                             "evidence_json=? WHERE id=?", (inc.start_ms, inc.end_ms, ch.cause.rule,
                                                                            _tags(inc), _evidence(inc, ch.cause), rid))
                self.on_incident(op, inc)
            elif ch.type == "final":
                f = ch.obj
                rid = self.rows.pop(f.incident.key, None)
                if rid is not None:
                    await self.store.execute("UPDATE incidents SET cause_final=?, cause_changed=?, primary_cause=?, "
                                             "evidence_json=? WHERE id=?",
                                             (f.cause.rule, int(f.changed), f.cause.rule, _evidence(f.incident, f.cause), rid))
