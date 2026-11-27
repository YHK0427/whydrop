[English](CONTRIBUTING.md) | **한국어**

# 기여하기

도와주셔서 고마워요. 가장 쓸모 있는 기여는 **잘못된 진단**이에요. whydrop이 잘못 설명한 끊김이나 놓친 끊김이요. *Wrong diagnosis* 템플릿으로 이슈를 열고 그 끊김의 버그 리포트(끊김 기록 → 그 끊김 → *버그 리포트 (JSON, 공개 보기)*)를 첨부해 주세요. 공개 보기를 쓰기 때문에 주소는 이미 지워져 있어요. 그래도 첨부하기 전에 한 번 읽어 보세요.

## 개발

```sh
git clone https://github.com/YHK0427/whydrop && cd whydrop
uv sync --all-extras
uv run pytest -q                                  # 단위, 통합, 웹
uv run playwright install chromium && uv run pytest -q -m ui tests/ui   # 실제 브라우저로 대시보드
uv run whydrop agent                              # 이 기기에서 기본 모드
```

Python 3.11~3.14. agent, 프로브, reflector는 표준 라이브러리만 쓰고, 대시보드만 FastAPI를 더해요. 계속 그렇게 유지해 주세요. 새 런타임 의존성에는 확실한 이유가 필요해요.

## 규칙 바꾸기

모든 기준값은 `src/whydrop/analysis/constants.py`에 있어요. 바꾸기 전에 실제 데이터로 다시 돌려 보세요.

```sh
uv run whydrop replay path/to/whydrop.db --set LAN_MISSES=3
```

그리고 PR에 끊김 수가 어떻게 바뀌었는지, 사라지거나 생긴 끊김이 왜 틀렸거나 맞는지 써 주세요. 바꾸기 전에는 실패하는 테스트가 없는 규칙 변경은 merge되기 어려워요.

## PR

- 테스트를 먼저, 그리고 `uv run pytest -q` 통과. `src/whydrop/web/static`을 건드렸다면 UI 테스트도.
- 모든 Markdown 문서는 영어 `X.md`와 한국어 `X.ko.md` 짝이에요. 둘 다 고쳐 주세요(`scripts/check_doc_pairs.py`가 짝이 있는지 확인해요). 한쪽 언어가 어렵다면 PR에 그렇다고 써 주세요. 채워 넣을게요.
- 테스트, 문서, 스크린샷에 실제 주소, 와이파이 이름, MAC, BSSID를 절대 넣지 마세요. 문서용 대역(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)을 쓰세요. `scripts/scan_public.py`와 테스트가 문서를 확인해요.
- 파일에 비밀값 금지. `WHYDROP_SECRET`과 `WHYDROP_UI_TOKEN`은 환경 변수로만 받아요.

## 코드 스타일

작은 함수, 무엇인지 말해 주는 이름, *왜*를 말하는 주석. 모든 원인 문구에는 "추정"이 들어가요.
