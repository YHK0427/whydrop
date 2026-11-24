"""Every analysis threshold from spec §6 in one place; `whydrop replay --set NAME=VALUE` overrides them."""

FINALIZE_LAG_MS = 14_000         # the engine runs this far behind: late replies arrive up to timeout + 10 s
MAX_TIMEOUT_S = 3                # the longest probe timeout (dns_tcp, canary stall)
MAX_BACKLOG_S = 600              # frames are never built further back than this (old or skewed timestamps)
LAG_SPAN_CAP_S = 600             # an agent_lag whose end never arrived stops counting after this

# segments (§6.2)
LOCAL_STALE_S = 60               # a down local segment whose probe stopped reporting this long is unknown again
LOCAL_HOLD_S = 3                 # host_net / wifi / link: down after, and recovered after, 3 s held
LAN_MISSES = 2                   # consecutive gateway non-replies
LINE_LOOKBACK_S = 3              # every line-quorum send in [T-3 s, T-timeout] failed
LINE_MIN_PROVIDERS = 2
LINE_MIN_SENDS = 3
LINE_RECOVER_S = 3
STREAM_LOSS_FRAC = 0.8           # udp_stream ≥ 80 % loss for 2 s (only with basic quorum failing too)
STREAM_LOSS_S = 2
GATE_LOSS_FRAC = 0.05            # lossy-period gate: line_hb loss ≥ 5 % over the 60 s before the start…
GATE_WINDOW_S = 60
GATE_SHORT_S = 10                # …and a down that recovers within 10 s is not an incident
DNS_WINDOW_INTERVALS = 3
DNS_MIN_ATTEMPTS = 2
LATE_QUEUEING_FRAC = 0.5
RESUME_GRACE_S = 30              # no decisions until resume + 30 s

# conditions (§6.2)
LOSS_STREAM_WINDOW_S = 30
LOSS_BASIC_WINDOW_S = 60
LOSS_FRAC = 0.05
LOSS_MIN_SENDS = 20              # don't call 1 lost out of 3 a loss condition
WEAK_DBM = -75
WEAK_BELOW_MEDIAN_DB = 10
WEAK_MIN_SAMPLES = 60            # signal readings in the hour before "weak" can be judged against their median
WIFI_LAN_LOSS_FRAC = 0.10
WIFI_LAN_WINDOW_S = 60
BUSY_LAG_MS = 10
LATENCY_WINDOW_S = 30
LATENCY_FACTOR = 3.0
LATENCY_PLUS_MS = 50
GW_TIMEOUT_LEAD_S = 3            # router-check timeouts this long before a late-reply drop still count as in-home
LATENCY_MIN_PROVIDERS = 2
BASELINE_NONE_S = 3600           # R7 not evaluated in the first hour
BASELINE_LEARNING_S = 24 * 3600
DEGRADED_AFTER_S = 30

# incidents (§6.2)
MERGE_AFTER_END_S = 10
MERGE_AFTER_LOCAL_S = 120
LONG_OUTAGE_S = 3600
DATA_GAP_S = 60                  # no probe reported for longer (agent stopped, clock stepped): an open drop ends there
SETTLE_S = 80

# causes (§6.4)
R1A_BEFORE_S, R1A_AFTER_S = 5, 15
R1C_WINDOW_S = 5
ROAM_LOSS_WINDOW_S = 5           # a roam with loss within ±5 s is a point event
R4_AFTER_S = 60
R5_MARGIN_S = 5
NAT_RESET_WINDOW_S = 10
QUEUE_LOOKBACK_S = 10


def override(name: str, value: str) -> None:
    """`--set NAME=VALUE` for replay: only existing numeric constants, same type."""
    g = globals()
    if name not in g or name.startswith("_") or not isinstance(g[name], (int, float)) or isinstance(g[name], bool):
        raise KeyError(f"unknown constant {name}")
    g[name] = type(g[name])(float(value)) if isinstance(g[name], int) else float(value)
