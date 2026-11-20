# whydrop 와이어 프로토콜 (v1)

[English](protocol.md) | **한국어**

whydrop agent는 **포트 48100**에서 내 reflector와 UDP(WD 패킷)와 TCP(WT 메시지)로 통신한다. 이 문서는 바이트 단위 명세다. `src/whydrop/proto/`의 코드가 이대로 구현하고, Wireshark 분석기도 이대로 해석한다.

규칙: 모든 정수는 **빅엔디언**(네트워크 바이트 순서)이다. IPv4만 쓴다. `HMAC8(k, m)`은 키 `k`로 `m`에 대해 계산한 HMAC-SHA256의 앞 8바이트다. 키는 공유 비밀값 `WHYDROP_SECRET`(32바이트 이상)이다.

## 메시지 크기

| 메시지 | 전송 계층 | 크기 |
|---|---|---|
| `WD` | UDP | 44 B |
| `NONCE` | TCP | 20 B |
| `HELLO` | TCP | 30 B |
| `HELLO_OK` | TCP | 16 B |
| `AUTH_FAIL` | TCP | 4 B |
| `VERSION` | TCP | 4 B |
| `BUSY` | TCP | 4 B |
| `FRAME` | TCP | 16 B |

## UDP: WD 패킷

WD 패킷은 항상 44바이트다:

| 오프셋 | 필드 | 크기 | 뜻 |
|---|---|---|---|
| 0 | magic | 2 | `"WD"` |
| 2 | version | 1 | `1` |
| 3 | type | 1 | 1 = PROBE, 2 = ECHO, 3 = NAT_REQ, 4 = NAT_REPLY |
| 4 | session_id | 4 | agent를 실행할 때마다 무작위. nat-test는 소켓마다 하나씩 씀 |
| 8 | seq | 4 | 보낸 순서 번호 |
| 12 | t_send_ns | 8 | agent의 단조 시계로 잰 보낸 시각. 그대로 돌려받음 |
| 20 | recv_count | 4 | ECHO: 이 세션에서 reflector가 받은 서로 다른 PROBE 수 |
| 24 | epoch | 4 | ECHO / NAT_REPLY: reflector가 켜질 때 정하는 무작위 ID |
| 28 | rx_bitmap | 4 | ECHO: *i*번 비트(0번 = 최하위 비트)가 켜져 있으면 seq − 1 − *i*를 받았다는 뜻 |
| 32 | arg | 4 | NAT_REQ: 지연 시간(초). NAT_REPLY: 0 = 즉시, 1 = 지연. ECHO: 지금까지 reflector 자기 소켓에서 버려진 수신 패킷 수 (Linux만. 다른 OS에서는 0) |
| 36 | hmac | 8 | `HMAC8(secret, 0–35번 바이트)` |

**PROBE → ECHO.** agent가 PROBE를 보낸다 (정밀 모드에서 초당 10개). reflector는 처음 보는 seq마다 ECHO 하나로 답하고, session_id, seq, t_send_ns를 그대로 담는다.

**NAT_REQ → NAT_REPLY.** `arg`는 10, 20, 30, 45, 60, 90, 120, 180, 300, 600 중 하나여야 한다. reflector는 바로 NAT_REPLY(arg = 0)로 답하고, 지연 시간이 지난 뒤 요청이 온 주소로 NAT_REPLY(arg = 1)를 한 번 더 보낸다. 두 번째 답이 오지 않으면, 경로에 있는 NAT나 방화벽이 지연 시간이 끝나기 전에 매핑을 잊은 것이다. 같은 세션에서 새 NAT_REQ가 오면 기다리던 요청을 대신하고 지연을 처음부터 다시 잰다.

### 패킷은 어느 쪽에서 사라졌나
ECHO를 못 받은 seq가 있으면, 그 뒤 32개 안에서 처음 받은 ECHO를 본다. 그 ECHO의 rx_bitmap에서 해당 seq의 비트가 켜져 있으면 reflector는 PROBE를 받았고 ECHO가 **내려오는 길**에서 사라진 것이다. 비트가 꺼져 있으면 PROBE가 **올라가는 길**에서 사라진 것이다. 32개보다 멀면 방향을 알 수 없다.

끊긴 구간 전체는 끊기기 전 마지막 ECHO(*a*)와 복구 후 첫 ECHO(*b*)로 계산한다:
- 업로드 손실 = (seq_b − seq_a) − (recv_count_b − recv_count_a)
- 다운로드 손실 = (recv_count_b − recv_count_a) − (seq_a, seq_b] 구간 seq에 대해 받은 ECHO 수 (ECHO_b 포함)
- b 자신의 PROBE만 도착했다면 업로드가 100% 손실된 것이고, 다운로드는 측정할 수 없다.
- epoch가 바뀌었거나 recv_count가 줄었다면 reflector가 재시작된 것이고, 방향은 알 수 없다.

## TCP: 핸드셰이크

reflector가 먼저 말한다:

| 메시지 | 방향 | 구성 | 크기 |
|---|---|---|---|
| `NONCE` | reflector → agent | `"WT"` version(1) type=1 nonce(16) | 20 B |
| `HELLO` | agent → reflector | `"WT"` version(1) type=2 role(1) reserved(1) session_id(4) param_s(4) anonce(8) hmac(8) | 30 B |
| `HELLO_OK` | reflector → agent | `"WT"` version(1) type=3 epoch(4) hmac(8) | 16 B |
| `AUTH_FAIL` | reflector → agent | `"WT"` version(1) type=4, 그다음 연결 종료 | 4 B |
| `VERSION` | reflector → agent | `"WT"` version(1) type=5, 그다음 연결 종료 | 4 B |
| `BUSY` | reflector → agent | `"WT"` version(1) type=6, 그다음 연결 종료 | 4 B |

- HELLO의 hmac = `HMAC8(secret, nonce ‖ HELLO 0–21번 바이트)`. nonce가 연결마다 새로 정해지므로, 녹화해둔 HELLO를 다시 보내도 통하지 않는다.
- HELLO_OK의 hmac = `HMAC8(secret, anonce ‖ HELLO_OK 0–7번 바이트)`. `anonce`는 agent가 정한 무작위 8바이트다. 그래서 agent는 주소를 가로챈 다른 무언가가 아니라 자기 reflector와 말하고 있다는 걸 확인할 수 있다.
- **role**과 **param_s**:
  - 1 = hot: `param_s`는 0이어야 한다.
  - 2 = idle: `param_s`는 ping 간격, 30–7500초.
  - 3 = nat: `param_s`는 60, 300, 600, 1200, 1800, 3600 중 하나 (7500은 reflector를 `--enable-7500`으로 켰을 때만).
- 버전이 다르면 `VERSION`, MAC이 틀리면 `AUTH_FAIL`, reflector가 지원하지 않는 `param_s`면 `VERSION`을 받는다. 5초 안에 HELLO를 다 보내지 않은 연결은 닫힌다.

## TCP: HELLO_OK 이후 프레임

프레임은 모두 16바이트다:

| 메시지 | 방향 | 구성 | 크기 |
|---|---|---|---|
| `FRAME` | 양방향 | type(1) flags(1) reserved(2) seq(4) t_send_ns(8) | 16 B |

| type | 이름 | 방향 | 쓰임 |
|---|---|---|---|
| 0x10 | HB | agent → reflector | hot: 1초마다 |
| 0x11 | HB_ACK | reflector → agent | HB에 같은 seq와 t_send_ns로 답함 |
| 0x20 | IDLE_PING | reflector → agent | idle: `param_s`초마다, reflector가 먼저 보냄 |
| 0x21 | IDLE_PONG | agent → reflector | IDLE_PING에 대한 답 |
| 0x30 | NAT_PROBE | reflector → agent | nat: `param_s`초 뒤 한 번 보내고 reflector가 연결을 닫음 |

idle ping을 reflector가 먼저 보내는 데는 이유가 있다. agent가 먼저 보내면, 연결을 잊어버린 NAT가 그 패킷으로 상태를 슬쩍 다시 만들어서 상태가 사라졌다는 사실이 드러나지 않는다.

## reflector가 절대 하지 않는 것

- UDP에서는 MAC이 틀린 패킷에 답하지 않고, MAC을 확인하기 전에는 아무 상태도 만들지 않는다. (TCP에서는 틀린 HELLO에 4바이트 `AUTH_FAIL`로 답하고, 그 연결은 HELLO 전 슬롯 하나를 최대 5초 동안 차지한다. 이 슬롯은 수가 제한되어 있다.)
- 답은 요청보다 크지 않고 (44 B에는 44 B), NAT_REQ 하나에는 답이 최대 두 번이다.
- **들어오는** ECHO와 NAT_REPLY는 버린다. 그래서 자기가 보낸 답을 다시 튕겨내게 만들 수 없다.
- (세션, seq) 하나에는 한 번만 답한다. 세션별 가장 큰 seq를 디스크에 7일 동안 보관하므로, 재시작 전에 녹화한 패킷을 보내도 답이 오지 않는다. 이 파일은 10초마다 쓰므로, 정상 종료가 아니라 비정상 종료라면 그 직전 몇 초 동안의 패킷에는 한 번 답할 수 있다.

## 제한

| 항목 | 제한 |
|---|---|
| MAC 확인 전 UDP | 출발지 IP당 초당 200개 |
| MAC 확인 후 UDP | 출발지 IP당 초당 50개 |
| 대기 중인 NAT_REQ | 세션당 1개, 출발지 IP당 16개, 전체 1024개 |
| HELLO 전 TCP 연결 | 출발지 IP당 4개, 전체 64개 |
| HELLO_OK 후 TCP 연결 | 세션당 hot 1개와 idle 1개 (새 HELLO가 오면 옛 연결을 대신함), 세션당 nat 7개, 전체 256개. 넘으면 `BUSY` |
| HB가 없는 hot 연결 | 30초 뒤 닫힘 |
