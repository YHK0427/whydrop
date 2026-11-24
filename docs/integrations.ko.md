[English](integrations.md)

# Prometheus, Grafana, Home Assistant

whydrop은 자체 대시보드가 있지만, 상태와 알림을 홈랩에서 이미 쓰는 도구에 붙일 수 있어요. 아래 예시는 모두 대시보드 토큰(`docker compose exec whydrop cat /data/ui-token`)과 대시보드가 듣는 주소(기본 포트 `8790`, 아래 `WHYDROP_IP` 자리에 넣으세요)를 써요. IP가 아니라 호스트 이름으로 접속한다면 그 이름을 `whydrop.toml`의 `web.allowed_hosts`에 넣으세요.

## Prometheus

`GET /api/metrics`는 Prometheus 텍스트 형식으로 답해요. 라벨에는 주소가 들어가지 않아요. DNS 서버는 IP 대신 종류(`dns_router`, `dns_isp`, `dns_public`)로 나와요.

```yaml
# prometheus.yml
scrape_configs:
  - job_name: whydrop
    metrics_path: /api/metrics
    scrape_interval: 30s
    authorization:
      credentials_file: /etc/prometheus/whydrop-token   # 대시보드 토큰만 들어 있는 파일
    static_configs:
      - targets: ["WHYDROP_IP:8790"]
```

| 메트릭 | 뜻 |
|---|---|
| `whydrop_segment_up{segment}` | 경로 구간마다 정상 1, 끊김 0: `host_net`, `wifi`, `link`, `lan`, `line`, `dns`. 모를 때는 값이 없어요. |
| `whydrop_probe_loss_ratio{probe,target}` | 마지막 완결된 1분(분석 지연을 감안해 15초 전에 끝난 1분) 동안 잃은 비율이에요. |
| `whydrop_probe_late_ratio{probe,target}` | 같은 1분 동안 시간 초과 뒤에 늦게 온 비율이에요. |
| `whydrop_probe_rtt_milliseconds{probe,target,stat}` | 같은 1분 동안의 RTT예요. `stat`은 `avg` 또는 `max`예요. |
| `whydrop_line_availability_ratio` | 이번 달 가용률이에요. 대시보드와 같은 값이에요(0–1). |
| `whydrop_month_drops`, `whydrop_month_down_seconds` | 이번 달 경로 끊김 횟수와 총 길이예요. |
| `whydrop_last_drop_end_timestamp_seconds{cause}` | 가장 최근 끊김이 끝난 시각이에요. `cause`는 규칙(R1a … R7, [설계](design.ko.md) 참고)이에요. |
| `whydrop_wifi_signal_dbm` | agent가 와이파이로 연결돼 있을 때의 신호 세기예요. |
| `whydrop_probe_bytes_total{probe}` | agent 시작 후 프로브가 쓴 바이트예요. |
| `whydrop_info{version,mode,link}` | 항상 1이에요. |

Grafana에서 쓰기 좋은 쿼리예요.

```promql
whydrop_segment_up{segment="line"}                                        # State timeline 패널
max by (target) (whydrop_probe_rtt_milliseconds{probe="gateway",stat="max"})   # 공유기 RTT: 집 안 대기열이 여기서 먼저 보여요
whydrop_probe_loss_ratio{probe="line_hb"}                                 # 공유기 너머 손실
changes(whydrop_last_drop_end_timestamp_seconds[1h])                      # 최근 1시간 끊김
```

whydrop 웹훅 대신 Alertmanager로 알림을 받고 싶다면 이런 규칙을 쓰면 돼요.

```yaml
groups:
  - name: whydrop
    rules:
      - alert: InternetLineDown
        expr: whydrop_segment_up{segment="line"} == 0
        for: 30s
```

Prometheus는 수집할 때마다 whydrop의 상태를 봐요. 원인과 판단 근거는 끊김이 끝나고 80–130초 뒤 판정이 확정될 때 나와요. "왜"는 대시보드나 아래 웹훅으로 확인하세요.

## Home Assistant

### 실시간 상태: REST 센서

```yaml
# configuration.yaml
rest:
  - resource: http://WHYDROP_IP:8790/api/status
    headers:
      Authorization: !secret whydrop_auth      # secrets.yaml: whydrop_auth: "Bearer <토큰>"
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

### 끊김마다 원인과 함께: 웹훅 트리거

whydrop 웹훅을 Home Assistant로 보내세요(`notify.webhook_url = "http://homeassistant.local:8123/api/webhook/whydrop-drop"`, `notify.format = "json"`). 본문에는 `title`, `text`(판정 문장), `drop`(공개 보기: 규칙, 구간, 근거)이 들어 있어요.

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

`webhook_id`는 길고 무작위로 정하세요. 네트워크 안에서 그 값을 아는 사람은 누구나 이 자동화를 실행할 수 있어요.
