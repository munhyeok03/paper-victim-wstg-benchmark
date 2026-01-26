# LLM Cyber Attack Bias - Attack Automation

LLM 보안 에이전트(Claude, Codex, Gemini)의 사이버 공격 수행 능력과 편향성을 비교 분석하는 자동화 실험 프레임워크.

## 프로젝트 목적

동일한 취약한 웹 애플리케이션을 대상으로 각 LLM 에이전트의:
- 공격 행동 패턴
- 취약점 발견 능력
- 공격 방법론 선택
- 윤리적 제한사항 반응

을 비교 분석한다.

## 핵심 아키텍처

```
                    ┌─────────────────┐
                    │  metrics-proxy  │ ◄── LiteLLM (토큰/비용 추적)
                    │   (port 4000)   │
                    └────────┬────────┘
           ┌─────────────────┼─────────────────┐
           │                 │                 │
┌──────────┴──────┬──────────┴──────┬──────────┴──────┐
│   net-codex     │   net-claude    │   net-gemini    │
│  ┌───────────┐  │  ┌───────────┐  │  ┌───────────┐  │
│  │  victim   │  │  │  victim   │  │  │  victim   │  │
│  └─────┬─────┘  │  └─────┬─────┘  │  └─────┬─────┘  │
│  ┌─────┴─────┐  │  ┌─────┴─────┐  │  ┌─────┴─────┐  │
│  │  agent-   │  │  │  agent-   │  │  │  agent-   │  │
│  │  codex    │  │  │  claude   │  │  │  gemini   │  │
│  └───────────┘  │  └───────────┘  │  └───────────┘  │
└─────────────────┴─────────────────┴─────────────────┘
```

- 각 에이전트는 **격리된 Docker 네트워크**에서 독립 victim과 함께 실행
- 에이전트 간 크로스 통신 불가 (공정한 비교 보장)
- **metrics-proxy**: 모든 API 호출을 중계하여 토큰/비용 메트릭 수집

## 디렉토리 구조

```
attack-automation/
├── agents/                    # 에이전트 Docker 설정
│   ├── base/Dockerfile        # Kali Linux 기반 이미지 (nmap, sqlmap, nikto 등)
│   ├── claude/                # Claude Code CLI
│   ├── codex/                 # OpenAI Codex CLI
│   ├── gemini/                # Google Gemini CLI
│   └── scripts/entrypoint.sh  # 공통 실행 스크립트
├── metrics/                   # 메트릭 수집
│   ├── litellm_config.yaml    # LiteLLM 프록시 설정
│   ├── custom_logger.py       # 커스텀 콜백 (usage.jsonl 기록)
│   └── logs/
│       ├── usage.jsonl        # API 호출별 전체 대화 + 메트릭
│       └── *_proxy.log        # 프록시 디버그 로그
├── scripts/                   # 유틸리티
│   └── aggregate_metrics.py   # 메트릭 집계 스크립트
├── prompts/                   # 공격 프롬프트 (example_*.txt만 git 추적)
│   └── example_attack.txt     # 예제 프롬프트 템플릿
├── output_formats/            # 출력 형식 템플릿 (example_*.txt만 git 추적)
│   ├── example_struct.txt     # JSONL 출력 템플릿
│   └── example_report.txt     # Markdown 보고서 템플릿
├── results/                   # 구조화된 결과 (JSONL/Markdown) + 세션 대화
├── docker-compose.yml         # 컨테이너 오케스트레이션
├── run.sh                     # 메인 실행 스크립트
├── .env                       # API 키 설정 (git ignore)
└── .env.example               # 환경 변수 템플릿
```

## 빠른 시작

### 1. 환경 설정
```bash
cp .env.example .env
# .env에 API 키 입력:
# - ANTHROPIC_API_KEY (Claude)
# - OPENAI_API_KEY (Codex)
# - GOOGLE_API_KEY (Gemini)
```

### 2. 실행
```bash
# 모든 에이전트, struct 모드
./run.sh --prompt prompts/attack.txt --all --mode struct

# Claude만, report 모드
./run.sh --prompt prompts/attack.txt --claude --mode report

# 커스텀 Docker 이미지 사용
./run.sh --prompt prompts/attack.txt --claude --victim myapp:v1 --victim-port 8080

# 이미지 강제 재빌드
./run.sh --prompt prompts/attack.txt --claude --build
```

## run.sh 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--prompt <file>` | 프롬프트 파일 (필수) | - |
| `--claude/--codex/--gemini/--all` | 에이전트 선택 (최소 1개 필수) | - |
| `--victim <type\|image>` | 프리셋 또는 Docker 이미지 태그 | `juice-shop` |
| `--victim-port <port>` | 커스텀 이미지의 포트 | `3000` |
| `--victim-healthcheck <url>` | 커스텀 이미지의 헬스체크 URL | `http://localhost:<port>` |
| `--mode <format>` | `report` (Markdown), `struct` (JSONL) | `report` |
| `--output-format <file>` | 커스텀 출력 형식 템플릿 | 기본 템플릿 |
| `--sequential` | 순차 실행 | 병렬 |
| `--keep` | 실행 후 컨테이너 유지 | 삭제 |
| `--build` | Docker 이미지 강제 재빌드 | - |

## 메트릭 수집

### LiteLLM 프록시

모든 에이전트의 API 호출은 `metrics-proxy`를 통해 라우팅됩니다:
- Claude: `ANTHROPIC_BASE_URL=http://metrics-proxy:4000`
- Codex: `OPENAI_BASE_URL=http://metrics-proxy:4000`
- Gemini: `GOOGLE_GEMINI_BASE_URL=http://metrics-proxy:4000`

### 수집 메트릭

```jsonl
{"timestamp":"2026-01-26T08:47:39Z","agent":"claude","model":"claude-opus-4-5-20251101","success":true,"latency_ms":2732.81,"prompt_tokens":74169,"completion_tokens":227,"total_tokens":74396,"cost_usd":0.0445}
```

| 필드 | 설명 |
|------|------|
| `agent` | 에이전트 타입 (claude, codex, gemini) |
| `model` | 사용된 모델 |
| `prompt_tokens` | 입력 토큰 수 |
| `completion_tokens` | 출력 토큰 수 |
| `cache_read_tokens` | 캐시에서 읽은 토큰 (Claude) |
| `cache_creation_tokens` | 캐시 생성 토큰 (Claude) |
| `cost_usd` | API 호출 비용 |
| `latency_ms` | 응답 지연시간 |

### 메트릭 집계

```bash
# 집계 스크립트 실행
python3 scripts/aggregate_metrics.py metrics/logs/ --output summary.json

# 출력 예시
{
  "models": {
    "claude-opus-4-5-20251101": {
      "calls": 55,
      "total_tokens": 2959616,
      "total_cost_usd": 2.31,
      "avg_latency_ms": 3722.7,
      "p95_latency_ms": 7058.16
    }
  }
}
```

## 출력 구조

### 디렉토리 분리

| 디렉토리 | 내용 | 용도 |
|----------|------|------|
| `results/` | 구조화된 결과 (JSONL/Markdown) + 세션 대화 | 취약점 분석 |
| `metrics/logs/` | 전체 API 호출 로그 (대화 내용 포함) | 분석/디버깅 |

### 대화 로그 (`metrics/logs/usage.jsonl`)

모든 API 호출의 전체 대화 내용이 LiteLLM 프록시를 통해 자동 캡처됩니다:

```jsonl
{
  "timestamp": "2026-01-26T08:47:39Z",
  "agent": "claude",
  "model": "claude-opus-4-5-20251101",
  "success": true,
  "latency_ms": 2732.81,
  "prompt_tokens": 74169,
  "completion_tokens": 227,
  "messages": [
    {"role": "user", "content": "Target: http://victim:3000\n\nPerform security..."},
    {"role": "assistant", "content": "I'll begin the assessment..."}
  ],
  "response": "I'll begin the security assessment by running nmap...",
  "cost_usd": 0.0445
}
```

| 필드 | 설명 |
|------|------|
| `messages` | 전체 입력 메시지 배열 (대화 히스토리) |
| `response` | 모델 응답 텍스트 |

### 세션별 대화 추출

각 실행 세션의 대화가 에이전트별로 분리되어 자동 추출됩니다:
- `results/{timestamp}_{agent}_conversations.jsonl`
- 예: `20260126_110000_claude_conversations.jsonl`

### Struct 모드 (`--mode struct`)
```jsonl
{"timestamp":"...","phase":"recon","action":"nmap_scan","target":"victim:3000","result":"Port 3000 open","success":true}
{"timestamp":"...","phase":"vuln","action":"sql_injection","target":"/api/login","result":"Auth bypass","success":true,"details":{"severity":"CRITICAL"}}
```

**phase 값**: `recon`, `enum`, `vuln`, `exploit`, `post`

## 에이전트별 설정

### 사용 모델

| Agent | Model | 비고 |
|-------|-------|------|
| Claude | `claude-opus-4-5-20251101` | 모든 요청 Opus로 통일 (프록시 리다이렉트) |
| Codex | `gpt-5.2-codex` | 조직 인증 필요 |
| Gemini | `gemini-3-pro-preview` | - |

### CLI 실행 명령

| Agent | 명령 |
|-------|------|
| Claude | `claude --model claude-opus-4-5-20251101 --print --dangerously-skip-permissions "$PROMPT"` |
| Codex | `codex exec --model gpt-5.2-codex --yolo --skip-git-repo-check "$PROMPT"` |
| Gemini | `gemini --model gemini-3-pro-preview -p "$PROMPT" --yolo` |

### 포함 도구 (Kali Linux)

- **스캐닝**: nmap, nikto, dirb
- **공격**: sqlmap
- **네트워크**: curl, wget, netcat, dnsutils
- **검색**: ripgrep (rg)
- **프로세스**: procps (ps, pgrep, pkill, top)
- **유틸리티**: jq, git, python3, nodejs

## Victim 서버 옵션

### 프리셋
| Type | 이미지 | 포트 |
|------|--------|------|
| `juice-shop` | `bkimminich/juice-shop` | 3000 |
| `webgoat` | `webgoat/webgoat` | 8080 |
| `vuln-shop` | `vuln-shop:latest` (로컬 빌드) | 3000 |

### 커스텀 이미지
```bash
./run.sh --prompt p.txt --claude --victim nginx:latest --victim-port 80
./run.sh --prompt p.txt --claude --victim myapp:v1 --victim-port 8080 \
    --victim-healthcheck "http://localhost:8080/health"
```

## 트러블슈팅

### Permission denied 에러
Docker BuildKit 캐시 문제. Dockerfile은 `COPY --chmod=755`를 사용하지만, 캐시된 이미지가 있으면 발생할 수 있음:
```bash
./run.sh --prompt prompts/attack.txt --claude --build
```

### Codex 조직 인증 에러
```
Your organization must be verified to generate reasoning summaries
```
OpenAI 조직 인증 필요: https://platform.openai.com/settings/organization/general

### Claude 모델 통일
Claude Code CLI가 내부적으로 Haiku/Sonnet을 사용할 수 있으나, `metrics/litellm_config.yaml`에서 모든 요청을 Opus로 리다이렉트하도록 설정됨.

### 메트릭 미수집
```bash
# 프록시 상태 확인
docker logs metrics-proxy | tail -20

# usage.jsonl 확인
cat metrics/logs/usage.jsonl
```

## 주의사항

- 이 도구는 **교육 및 연구 목적**으로만 사용
- **승인된 환경**에서만 보안 테스트 수행
- 실제 시스템에 대한 무단 공격은 불법
