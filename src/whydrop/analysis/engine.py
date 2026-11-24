"""One step per second: frames → segments → conditions → incidents → causes (spec §6.1). Live and replay share it."""
from collections import deque
from dataclasses import dataclass

from whydrop.analysis.causes import Settler, classify, label_period, protocol_paragraph
from whydrop.analysis.conditions import Conditions
from whydrop.analysis.explain import explain
from whydrop.analysis.incidents import Incident, Incidents
from whydrop.analysis.model import Context, Frame
from whydrop.analysis.segments import Segments

HISTORY_FRAMES = 900   # 15 min: enough for every rule window (R4 60 s after end + settle 80 s, queueing 10 s)


@dataclass
class Change:
    type: str          # "segment" | "condition" | "incident" | "final" | "finding"
    obj: object
    cause: object = None


class Engine:
    def __init__(self, ctx: Context, reopen: list[Incident] | None = None):
        self.ctx = ctx
        self.seg, self.cond = Segments(ctx), Conditions(ctx)
        self.inc, self.settle = Incidents(ctx, reopen=reopen), Settler(ctx)
        self.frames: deque[Frame] = deque(maxlen=HISTORY_FRAMES)

    def step(self, frame: Frame) -> list[Change]:
        self.frames.append(frame)
        sc = self.seg.step(frame)
        cc = self.cond.step(frame, self.seg)
        ic = self.inc.step(frame, sc, cc, self.seg)
        finals = self.settle.step(frame, ic, self.frames, self.cond)
        out = [Change("segment", c) for c in sc]
        out += [Change("condition", c, label_period(c.kind, self.ctx, self.cond.line_hb_lossy(), self.cond.loss_at_home())
                       if c.phase == "start" else None) for c in cc]
        for c in ic:
            if c.op == "finding":
                out.append(Change("finding", c))
            else:
                out.append(Change("incident", c, classify(c.incident, self.frames, self.cond, self.ctx)))
        for f in finals:
            f.incident.evidence["protocol"] = protocol_paragraph(f.incident)
            f.incident.evidence["protocol_ko"] = protocol_paragraph(f.incident, "ko")
            f.incident.evidence.update(explain(f.incident, self.frames, self.ctx, f.cause.rule))   # facts and ruled_out
            out.append(Change("final", f, f.cause))
        return out
