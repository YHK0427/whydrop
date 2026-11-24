[English](deploy-reflector.md) | **한국어**

# reflector 배포하기

reflector가 있어야 정밀 모드가 켜져요. 업로드/다운로드 구분, TCP 카나리아, `nat-test`가 여기에 달려 있어요. reflector는 작은 whydrop 프로세스(표준 라이브러리만 씀)이고, 포트 하나(48100)에서 UDP와 TCP로 인증된 패킷에만 답해요.

## 필요한 것

- **집 네트워크 밖에 있는**, 공인 IPv4 주소가 있는 Linux 기기. 아무 VPS나 클라우드의 무료 티어 VM이면 돼요. 가까운 지역을 고르세요. 그곳까지의 왕복 시간이 모든 정밀 측정의 기준선이 돼요.
- 들어오는 UDP **와** TCP 48100 허용. 클라우드 쪽 방화벽(보안 그룹 / 보안 목록)과 기기 자체 둘 다에서요.
- Docker, 또는 Python 3.11~3.13.

reflector 하나와 비밀값 하나로 agent 여러 개를 받을 수 있어요.

## 1. 비밀값 만들기

아무 기기에서나:

```sh
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

안전한 곳에 보관하세요. 32바이트 이상이어야 하고, 예시 값은 reflector와 agent 둘 다 거부해요. 비밀값은 로그에 남지 않고, 대시보드나 API에도 나오지 않아요.

## 2. reflector 실행하기

Docker로:

```sh
git clone https://github.com/YHK0427/whydrop && cd whydrop
docker build -t whydrop .
docker run -d --name whydrop-reflector --restart unless-stopped \
  -p 48100:48100/udp -p 48100:48100/tcp \
  -e WHYDROP_SECRET='여기에-비밀값' \
  -v whydrop-reflector:/data --read-only --cap-drop ALL --security-opt no-new-privileges \
  whydrop reflector --state-dir /data
docker logs whydrop-reflector
```

`whydrop reflector … listening udp :48100 tcp :48100`이 보이면 돼요.

Docker 없이(소스에서 `pip install .` 한 뒤):

```sh
WHYDROP_SECRET='여기에-비밀값' whydrop reflector --state-dir /var/lib/whydrop-reflector
```

`--state-dir`에는 재생 방지 기록(세션마다 본 가장 큰 순번)이 저장돼요. 이 덕분에 가로챈 패킷은 재시작 뒤에도 쓸모가 없어요. 사라지지 않는 저장소에 두세요.

옵션: `--port`(기본 48100), `--host`(기본 0.0.0.0), `--enable-7500`(`nat-test`의 7500초 TCP 대기를 허용. 연결 하나를 두 시간 동안 열어 두기 때문에 기본은 꺼져 있어요). 에이전트는 `whydrop nat-test --enable-7500`이나 에이전트 쪽 `whydrop.toml`의 `[nat] enable_7500 = true`일 때만 이 대기를 요청해요.

## 3. 포트 열기

클라우드 콘솔에서 들어오는 **UDP 48100**과 **TCP 48100**을 모든 곳에서(집 공인 IP가 바뀌지 않는다면 그 주소에서만) 허용하세요. 그다음 기기에 방화벽이 돌고 있다면:

```sh
sudo ufw allow 48100/udp && sudo ufw allow 48100/tcp          # ufw를 쓰는 Ubuntu
```

어떤 이미지는 ufw가 없어도, 명시적으로 허용하지 않은 것을 전부 거부하는 iptables 규칙을 기본으로 갖고 있어요. `sudo iptables -L INPUT -n`으로 확인하고, 필요하면 두 프로토콜의 `ACCEPT` 규칙을 `REJECT`보다 앞에 넣으세요.

## 4. agent에 알려 주기

agent의 `compose.yaml` 옆 `.env`에:

```sh
WHYDROP_REFLECTOR=reflector.주소      # host 또는 host:port
WHYDROP_SECRET=여기에-비밀값
```

그리고 `docker compose up -d`. 대시보드의 지금 페이지에서 TCP 줄이 hot 연결을 보여 주기 시작해요. 정밀 모드를 켤 수 없으면 `docker compose logs whydrop`에 이유가 나와요(`precision mode off: WHYDROP_SECRET not set` 등). reflector가 비밀값을 거부하면 대시보드에 그렇다는 배너가 떠요. `docker compose exec whydrop whydrop nat-test`로 전체 경로를 한 번 시험해 보세요.

## 돌려도 안전한가요?

- 비밀값이 없으면 reflector는 아무것에도 답하지 않아요. 모든 UDP 패킷은 올바른 HMAC을 가져야 하고, 모든 TCP 연결은 먼저 nonce 확인을 통과해야 해요.
- 트래픽 증폭에 쓸 수 없어요. 응답은 요청보다 크지 않고, NAT 시험 요청 하나에는 최대 두 번만 답해요.
- 크기, magic, 타입이 틀린 쓰레기 패킷은 해시 계산 전에 버리고, 출발지 IP마다 HMAC 확인 앞뒤로 속도를 제한해요.
- 순번 하나에는 한 번만 답해요. 다시 보낸 패킷에는 아무 응답이 없어요.
- 패킷 내용은 기록하지 않아요. 버린 패킷 수를 이유별로 1분마다 기록할 뿐이에요.

자세한 내용은 [design의 보안](design.ko.md#보안)에, 와이어 형식은 [protocol](protocol.ko.md)에 있어요.

## 비용

정밀 모드 agent 하나의 트래픽은 양방향 합쳐 약 18.5 kbit/s, 한 달에 약 6 GB예요. 저희가 아는 무료 티어 안에는 다 들어가지만, 쓰는 클라우드의 외부 전송 한도를 확인해 보세요.
