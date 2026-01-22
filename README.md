# LLM Cyber Attack Bias - Attack Automation Framework

LLM 기반 보안 에이전트들의 사이버 공격 수행 능력과 편향성을 비교 분석하기 위한 자동화 실험 프레임워크입니다.

## 개요

이 프로젝트는 다양한 LLM 에이전트(Claude, Codex, Gemini)가 동일한 취약한 웹 애플리케이션을 대상으로 침투 테스트를 수행할 때의 행동 패턴, 발견 취약점, 공격 방법론을 비교 분석합니다.

### 주요 특징

- **격리된 실험 환경**: 각 에이전트는 독립된 Docker 네트워크에서 자체 victim 서버와 함께 실행
- **다양한 Victim 지원**: OWASP Juice Shop, WebGoat, vuln-shop
- **병렬/순차 실행**: 여러 에이전트를 동시에 또는 순차적으로 실행 가능
- **구조화된 출력**: Markdown 보고서 또는 JSONL 형식으로 결과 저장

## 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                    Attack Automation                         │
├─────────────────┬─────────────────┬─────────────────────────┤
│   net-codex     │   net-claude    │      net-gemini         │
│  ┌───────────┐  │  ┌───────────┐  │     ┌───────────┐       │
│  │  victim   │  │  │  victim   │  │     │  victim   │       │
│  │  (Juice   │  │  │  (Juice   │  │     │  (Juice   │       │
│  │   Shop)   │  │  │   Shop)   │  │     │   Shop)   │       │
│  └─────┬─────┘  │  └─────┬─────┘  │     └─────┬─────┘       │
│        │        │        │        │           │             │
│  ┌─────┴─────┐  │  ┌─────┴─────┐  │     ┌─────┴─────┐       │
│  │  agent-   │  │  │  agent-   │  │     │  agent-   │       │
│  │  codex    │  │  │  claude   │  │     │  gemini   │       │
│  │  (Kali)   │  │  │  (Kali)   │  │     │  (Kali)   │       │
│  └───────────┘  │  └───────────┘  │     └───────────┘       │
└─────────────────┴─────────────────┴─────────────────────────┘
```

## 설치

### 요구사항

- Docker & Docker Compose
- API Keys:
  - OpenAI API Key (Codex)
  - Anthropic API Key (Claude)
  - Google API Key (Gemini)

### 설정

1. 환경 변수 설정:
```bash
cp .env.example .env
# .env 파일에 API 키 입력
```

2. Victim 서버 클론 (선택사항):
```bash
mkdir -p victims
cd victims
git clone https://github.com/juice-shop/juice-shop.git
git clone https://github.com/WebGoat/WebGoat.git
git clone https://github.com/taeng0204/vuln-shop.git
```

## 사용법

### 기본 실행

```bash
# Claude 에이전트로 Juice Shop 테스트
./run.sh --prompt prompts/example_attack.txt --claude

# Codex 에이전트로 테스트
./run.sh --prompt prompts/example_attack.txt --codex

# 모든 에이전트 병렬 실행
./run.sh --prompt prompts/example_attack.txt --all
```

### 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--prompt <file>` | 프롬프트 파일 경로 (필수) | - |
| `--claude` | Claude 에이전트 사용 | - |
| `--codex` | Codex 에이전트 사용 | - |
| `--gemini` | Gemini 에이전트 사용 | - |
| `--all` | 모든 에이전트 사용 | - |
| `--victim <type>` | Victim 서버 선택 | `juice-shop` |
| `--mode <format>` | 출력 형식 (report/struct) | `report` |
| `--output-format <file>` | 커스텀 출력 형식 템플릿 | 기본 템플릿 |
| `--sequential` | 순차 실행 | 병렬 |
| `--keep` | 실행 후 컨테이너 유지 | 삭제 |
| `--build` | Docker 이미지 강제 재빌드 | - |

### Victim 서버 옵션

| 옵션 | 설명 | Docker 이미지 |
|------|------|---------------|
| `juice-shop` | OWASP Juice Shop | `bkimminich/juice-shop` |
| `webgoat` | OWASP WebGoat | `webgoat/webgoat` |
| `vuln-shop` | 커스텀 취약 쇼핑몰 | `./victims/vuln-shop` (빌드) |

### 예시

```bash
# WebGoat으로 Claude 테스트
./run.sh --prompt prompts/example_attack.txt --claude --victim webgoat

# JSONL 형식으로 모든 에이전트 순차 실행
./run.sh --prompt prompts/example_attack.txt --all --mode struct --sequential

# vuln-shop으로 테스트 (자동 빌드)
./run.sh --prompt prompts/example_attack.txt --claude --victim vuln-shop
```

## 프로젝트 구조

```
attack-automation/
├── agents/                    # 에이전트 Docker 설정
│   ├── base/                  # 기본 Kali Linux 이미지
│   │   └── Dockerfile
│   ├── claude/                # Claude Code CLI
│   │   ├── Dockerfile
│   │   └── config/
│   ├── codex/                 # OpenAI Codex CLI
│   │   ├── Dockerfile
│   │   └── config/
│   ├── gemini/                # Google Gemini CLI
│   │   ├── Dockerfile
│   │   └── config/
│   └── scripts/
│       └── entrypoint.sh      # 공통 실행 스크립트
├── prompts/                   # 공격 프롬프트 템플릿
│   ├── example_attack.txt
│   └── templates/
├── output_formats/            # 출력 형식 템플릿
│   ├── example_struct.txt     # JSONL 출력 템플릿
│   └── example_report.txt     # Markdown 보고서 템플릿
├── results/                   # 구조화된 결과 (JSONL/Markdown)
├── logs/                      # 모델 원본 출력 (디버깅용)
├── victims/                   # Victim 서버 소스 (선택사항)
│   ├── juice-shop/
│   ├── WebGoat/
│   └── vuln-shop/
├── docker-compose.yml         # 컨테이너 오케스트레이션
├── run.sh                     # 메인 실행 스크립트
├── .env                       # API 키 설정
└── .env.example               # 환경 변수 템플릿
```

## 출력 구조

### 로그와 결과 분리

실행 결과는 두 가지로 분리되어 저장됩니다:

| 디렉토리 | 내용 | 용도 |
|----------|------|------|
| `logs/` | 모델의 전체 출력 (stdout/stderr) | 디버깅, 분석 |
| `results/` | 구조화된 결과 (JSONL/Markdown) | 데이터 분석 |

### 출력 형식 템플릿

`output_formats/` 디렉토리에 출력 형식 템플릿이 저장됩니다:

- `example_struct.txt` - JSONL 출력 템플릿 (기본)
- `example_report.txt` - Markdown 보고서 템플릿 (기본)

커스텀 템플릿 사용:
```bash
./run.sh --prompt prompts/attack.txt --claude --mode struct \
    --output-format output_formats/my_custom.txt
```

템플릿 파일에서 `{{RESULT_FILE}}` 플레이스홀더가 실제 결과 파일 경로로 치환됩니다.

## 결과 형식

### Report 모드 (Markdown)

```markdown
# Attack Report

## Summary
취약점 발견 개요

## Target Information
- Target URL/IP
- 식별된 서비스
- 기술 스택

## Vulnerabilities Found
발견된 취약점 목록 (심각도 포함)

## Exploitation Attempts
공격 시도 상세 내용

## Recommendations
보안 권고사항
```

### Struct 모드 (JSONL)

```json
{"timestamp":"2026-01-21T12:00:00Z","phase":"recon","action":"nmap_scan","target":"victim:3000","result":"Port 3000 open","success":true}
{"timestamp":"2026-01-21T12:01:00Z","phase":"vuln","action":"sql_injection","target":"/rest/user/login","result":"Auth bypass successful","success":true}
```

## 에이전트 도구

각 에이전트 컨테이너에는 다음 보안 도구가 포함됩니다:

- **네트워크 스캐닝**: nmap
- **웹 스캐닝**: nikto, dirb
- **SQL Injection**: sqlmap
- **HTTP 클라이언트**: curl, wget
- **유틸리티**: netcat, dnsutils, jq

## 라이선스

이 프로젝트는 교육 및 연구 목적으로만 사용되어야 합니다.
승인된 환경에서만 보안 테스트를 수행하세요.

## 참고

- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [Claude Code](https://docs.anthropic.com/claude-code)
- [OpenAI Codex](https://openai.com/codex)
