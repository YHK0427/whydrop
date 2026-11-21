# whydrop용 Wireshark dissector

[English](README.md) | **한국어**

`whydrop.lua`는 [docs/protocol](../../docs/protocol.ko.md)에 적힌 agent ↔ reflector 트래픽을 풀어 보여 줘요. UDP의 WD 패킷과 TCP의 WT 핸드셰이크·프레임을 다루고, 필드 이름은 그 문서와 같아요. 8바이트 MAC은 바이트로만 보여 주고 검증하지 않아요. 캡처에는 비밀값이 없으니까요.

## 설치
1. Wireshark에서 **Help → About Wireshark → Folders**를 열고 **Personal Lua Plugins** 경로를 확인하세요.
2. 그 폴더에 `whydrop.lua`를 복사하고 Wireshark를 다시 시작하세요(또는 Ctrl+Shift+L로 Lua 플러그인을 다시 읽기).
3. 필터에 `whydrop`을 쓰면 돼요. 기본 포트는 48100이고 **Preferences → Protocols → WHYDROP**에서 바꿀 수 있어요. 다른 UDP 포트의 WD 패킷은 모양(44바이트, `WD`로 시작)으로 찾아내요.

tshark에서는: `tshark -X lua_script:whydrop.lua -r capture.pcap -Y whydrop`.

## 어디를 보면 되나요
- 정밀 모드에서 끊김이 나면 PROBE는 계속 나가는데 ECHO가 멈춰요. 끊김 뒤 첫 ECHO의 `recv_count`와 `rx_bitmap`으로 업로드 손실과 다운로드 손실을 구분해요.
- hot 연결은 1초마다 `HB`를 보내요. 끊긴 동안에는 커널이 같은 `HB`를 점점 긴 간격으로 다시 보내는 모습(RTO가 두 배씩 늘어남)이 보여요.
