[한국어](integrations.ko.md)

# Prometheus, Grafana and Home Assistant

whydrop keeps its own dashboard, but its state and alerts plug into the tools a homelab already runs. Everything below uses the dashboard token (`docker compose exec whydrop cat /data/ui-token`) and the address the dashboard listens on (`8790` by default; replace `WHYDROP_IP` below with it). If you reach it by a hostname rather than an IP, add that name to `web.allowed_hosts` in `whydrop.toml`.

## Prometheus

`GET /api/metrics` returns the Prometheus text format. Labels never carry an address: a DNS server shows up as its class (`dns_router`, `dns_isp`, `dns_public`), not its IP.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: whydrop
    metrics_path: /api/metrics
    scrape_interval: 30s
    authorization:
      credentials_file: /etc/prometheus/whydrop-token   # the dashboard token, nothing else in the file
    static_configs:
      - targets: ["WHYDROP_IP:8790"]
```

| Metric | What it is |
|---|---|
| `whydrop_segment_up{segment}` | 1 up, 0 down, per hop of the path: `host_net`, `wifi`, `link`, `lan`, `line`, `dns`. Absent while unknown. |
| `whydrop_probe_loss_ratio{probe,target}` | Share lost over the last complete minute (the minute ending 15 s ago, after the analysis lag). |
| `whydrop_probe_late_ratio{probe,target}` | Share answered late (after the timeout) over the same minute. |
| `whydrop_probe_rtt_milliseconds{probe,target,stat}` | RTT over the same minute, `stat` = `avg` or `max`. |
| `whydrop_line_availability_ratio` | This month's availability, the dashboard's number (0–1). |
| `whydrop_month_drops`, `whydrop_month_down_seconds` | This month's drops on the path and their total length. |
| `whydrop_last_drop_end_timestamp_seconds{cause}` | When the latest drop ended; `cause` is its rule (R1a … R7, see [design](design.md)). |
| `whydrop_wifi_signal_dbm` | Wi-Fi signal, when the agent runs on Wi-Fi. |
| `whydrop_probe_bytes_total{probe}` | Bytes the probes used since the agent started. |
| `whydrop_info{version,mode,link}` | Always 1. |

Queries that work well in Grafana:

```promql
whydrop_segment_up{segment="line"}                                        # state timeline panel
max by (target) (whydrop_probe_rtt_milliseconds{probe="gateway",stat="max"})   # router RTT: in-home queueing shows here first
whydrop_probe_loss_ratio{probe="line_hb"}                                 # loss beyond the router
changes(whydrop_last_drop_end_timestamp_seconds[1h])                      # drops in the last hour
```

An alert rule, if you'd rather alert from Alertmanager than from whydrop's own webhooks:

```yaml
groups:
  - name: whydrop
    rules:
      - alert: InternetLineDown
        expr: whydrop_segment_up{segment="line"} == 0
        for: 30s
```

Prometheus sees whydrop's state every scrape; the cause and its evidence come with the finalized drop, 80–130 s after it ends. Open the dashboard (or use the webhook below) for the "why".

## Home Assistant

### Live state: a REST sensor

```yaml
# configuration.yaml
rest:
  - resource: http://WHYDROP_IP:8790/api/status
    headers:
      Authorization: !secret whydrop_auth      # secrets.yaml: whydrop_auth: "Bearer <token>"
    scan_interval: 15
    binary_sensor:
      - name: Internet line
        device_class: connectivity
        value_template: "{{ value_json.segments.line == 'up' }}"
      - name: Wi-Fi link
        device_class: connectivity
        value_template: "{{ value_json.segments.wifi == 'up' }}"
    sensor:
      - name: Line availability this month
        unit_of_measurement: "%"
        value_template: "{{ value_json.month.availability }}"
      - name: Drops this month
        value_template: "{{ value_json.month.drops }}"
```

### Each drop, with its cause: a webhook trigger

Point whydrop's webhook at Home Assistant (`notify.webhook_url = "http://homeassistant.local:8123/api/webhook/whydrop-drop"`, `notify.format = "json"`). The body carries `title`, `text` (the verdict sentence) and `drop` (public view: rule, segments, evidence).

```yaml
# automations.yaml
- alias: whydrop drop
  triggers:
    - trigger: webhook
      webhook_id: whydrop-drop
      allowed_methods: [POST]
      local_only: true
  actions:
    - action: notify.notify
      data:
        title: "{{ trigger.json.title }}"
        message: "{{ trigger.json.text }}"
```

Use a long random `webhook_id`: anyone on your network who knows it can trigger the automation.
