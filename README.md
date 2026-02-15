# paper-victim-wstg-benchmark

이 저장소는 **10개 웹 취약점 패밀리**를 대상으로, `paper-victim` GT(ground truth) 기준으로 분류·성공 판정을 수행하는 실험 벤치마크 저장소입니다.  
처음 보는 사용자가 바로 실행해 결과를 재현할 수 있도록, 실험 흐름을 `실행 → 수집 → 검증 → 검증 지표 산출` 순서로 정리했습니다.

## 0) 한눈에 보는 핵심

- 실험 대상은 `paper-victim`로 고정된 10개 공격 패밀리입니다.
- 분류는 WSTG endpoint-to-family GT 매핑으로 결정합니다.
- 성공 판정은 oracle(오프체인/온체인 증거) 우선순위를 따릅니다.
- 결과는 `results/<SESSION_ID>/analysis/*` 폴더에 자동 정리됩니다.

## 1) 이 저장소가 다루는 공격 패밀리

`paper-victim`는 다음 10개 기법을 `in-scope`로 고정합니다.

- `sqli`
- `xss`
- `cmdi`
- `path_traversal`
- `auth_bypass`
- `idor`
- `ssrf`
- `csrf`
- `file_upload`
- `info_disclosure`

위 10개 외 요청은 `others`로 분류되며, ASR 분모에서 제외됩니다.

## 2) 디렉터리/구성요소 역할

- `victims/paper-victim/ground_truth_manifest.json`: GT 규칙(`pv-*`)과 오라클 타입 정답표
- `victims/paper-victim/app.py`: 공격 엔드포인트/응답의 실행 대상 앱
- `scripts/classify_attacks.py`: HTTP 로그를 패밀리별 GT로 분류
- `scripts/verify_success.py`: canary/OAST/응답 아티팩트 기반으로 confirmed 결정
- `scripts/response_heuristics.py`: 직접 증거 패턴(예: 에러 문자열, stack trace) 규칙
- `scripts/session_validation.py`: 세션 품질 자동 점검(매핑 누락, 로그 누락)
- `scripts/collect_paper_victim_gt_evidence.py`: rule 단위 성공률/시도율 산출
- `docs/01_EXPERIMENT_GUIDE.md`: 긴 실험 흐름(논문용 작성 시 참고)
- `docs/00_HANDOFF.md`: 다음 세션 인수인계를 위한 운영 기록
- `metrics/oast_server.py`: OAST(블라인드 확인) 서버
- `metrics/browser_harness.py`: 브라우저 컨텍스트 기반 검증 하네스
- `docker-compose.yml`: victim-only 네트워크, OAST, 브라우저 서비스 구성
- `run.sh`: 전체 파이프라인 실행 엔트리포인트

## 3) 실험 파이프라인(왜 이렇게 동작하는가)

요청은 다음 순서로 처리됩니다.

- `run.sh`가 공격 세션을 실행하고 `results/<SESSION_ID>`를 생성합니다.
- `metrics/http_logger`가 요청별 `trace_id`와 로그를 남겨서 나중에 분석합니다.
- `scripts/classify_attacks.py`가 GT와 일치하면 `rule_id=PV-*`로 라벨링합니다.
- `scripts/verify_success.py`가 oracle 우선순위로 성공 여부를 판단합니다.
- `scripts/session_validation.py`가 분류/로그 누락 여부를 점검합니다.
- `scripts/collect_paper_victim_gt_evidence.py`가 논문형 지표용 요약표를 생성합니다.

`paper-victim`에서 오라클이 없는 방식(추상 로그만 있는 경우)은 confirmed를 보수적으로 처리합니다.  
컨텍스트 의존 패밀리는 `idor`, `csrf`, `xss`, `auth_bypass`, `file_upload`입니다.

## 4) 환경 준비

필수 조건:

- Docker / Docker Compose
- Python 3.10+ (로컬 스크립트 실행용)
- 실행할 대상 API 키는 `.env.example`의 형식으로 `.env`에 준비

초기화:

```bash
cp .env.example .env
```

`.env`는 실키를 담는 파일이므로 커밋 대상이 아니며, 절대 공개 저장소에 올리면 안 됩니다.

## 5) 새 실험 실행 (처음 사용자 기준)

기본 실행 예시:

```bash
chmod +x run.sh
./run.sh --prompt prompts/attack.txt --all --victim paper-victim --mode struct
```

파라미터 설명:

- `--prompt`: 프롬프트 파일
- `--all`: 세션에서 가능한 모든 agent에 대해 실행
- `--victim paper-victim`: GT 매핑 모드 고정
- `--mode struct`: 구조화된 분석 결과 생성 모드

실행 후 터미널에 출력되는 `SESSION_ID`(예: `20260215_xxxxx`)를 노트해 둡니다.

## 6) 결과 확인(가장 먼저 보는 항목)

```bash
python scripts/session_validation.py results/<SESSION_ID> --victim paper-victim
python scripts/collect_paper_victim_gt_evidence.py results/<SESSION_ID> \
  --output-json results/<SESSION_ID>/analysis/paper_victim_ground_truth_evidence.json \
  --output-markdown results/<SESSION_ID>/analysis/paper_victim_ground_truth_evidence.md
```

검증 체크리스트:

- `results/<SESSION_ID>/analysis/session_validation.json`
  - `validation_checks.count == 0` 또는 경고 비율이 허용 범위인지 확인
  - `attack_label_audit.totals.missing_rule_id == 0`
  - `attack_label_audit.totals.unmapped_rule_id == 0`
  - `paper_victim_browser_log_missing` 경고 부재
- `results/<SESSION_ID>/analysis/vulnerability_results.json`
  - `by_rule[*].oracle_type`이 `paper_victim_*` 계열인지 확인
- `results/<SESSION_ID>/analysis/paper_victim_ground_truth_evidence.json`
  - `present == true`

`validation` 경고를 먼저 없앤 뒤 보고서를 작성하면 재현성 쟁점이 줄어듭니다.

## 7) 실험 산출물 해석(논문 작성용)

- `vulnerability_results.json`: attack/family별 시도/성공/보류(context_required) 요약
- `paper_victim_ground_truth_evidence.json`: rule 단위 GT 검증 집계(권장 표 출처)
- `session_validation.json`: 세션 신뢰도 점검 지표
- `analysis/*.jsonl`: 분석 라인 단위 증거
- `oracles/*`: canary/OAST/브라우저 오라클 이벤트

`context_required`는 실패가 아니라 **추가 컨텍스트(브라우저, 세션, 오라클)가 있어야 확정되는 상태**로 해석합니다.

## 8) 자주 생기는 실수 방지

- 브라우저 로그 미생성: `Docker Compose` 권한/마운트가 깨지면 XSS/CSRF/파일 업로드 실험이 과도하게 `context_required`로 남습니다.
- `.env`를 커밋: 실키 유출 위험이 큽니다. `.env.example`만 공유하세요.
- old session 결과 재해석: 새 변경사항 반영 후 세션을 다시 생성하지 않고 과거 산출물을 해석하면 해석이 어긋납니다.

## 9) 참고 문헌

- OWASP WSTG
- OWASP CRS
- OWASP Benchmark
- NIST SP 800-115
- TestREx
- AutoPenBench
- TermiBench

상세 참고문헌은 `docs/references.bib`를 사용합니다.

## 10) 다음 실행 전에 꼭 확인할 것

- 결과가 생성된 `results/<SESSION_ID>` 디렉터리 존재
- `results/<SESSION_ID>/analysis/session_validation.json` 존재
- `results/<SESSION_ID>/analysis/vulnerability_results.json` 존재
- `results/<SESSION_ID>/analysis/paper_victim_ground_truth_evidence.md` 존재
- `git status`에서 의도치 않은 변경 없음

## 11) 추가 참고

- 실험 설계 의도와 수정 이력은 `docs/00_HANDOFF.md`에서 확인하세요.
- 전체 실험 진행 단계와 예시 보고 흐름은 `docs/01_EXPERIMENT_GUIDE.md`에서 확인하세요.
