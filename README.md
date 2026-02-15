# paper-victim-wstg-benchmark

**목적**

이 저장소는 10개 웹 공격 기법에 대해 **ground truth(GT) 기반 분류 및 성공 판정**을 적용해,
실험 재현성(reproducibility)과 판정 정합성(reliability)을 높이도록 설계된 벤치마크 파이프라인입니다.
핵심은 임의 임계치/휴리스틱이 아니라, `paper-victim`의 결정적 GT 매핑과 오라클 기반 증거로 성공 여부를 확정하는 것입니다.

---

## 1) 연구 범위 (paper-victim 기준 고정)

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

`others`는 위 10개에 포함되지 않는 요청이며, 분석 지표(ASR, confirmed rate)에서 분모로 제외합니다.

---

## 2) 핵심 설계 원칙 (논문형 평가 요건)

### 2.1 분류(Classification)

`paper-victim`은 endpoint-to-family GT 매핑을 사용합니다.  
`scripts/classify_attacks.py`에서 `--victim-type paper-victim` 옵션이 켜지면 CRS 점수 기반 탐지보다 우선 순위로 다음이 수행됩니다.

- endpoint 규칙( exact / prefix )으로 GT rule 매칭
- rule id (`pv-...`)
- `in_scope` / `out_of_scope` 분리

### 2.2 성공 판정(Verification)

`scripts/verify_success.py`는 성공을 다음 우선순위로 확정합니다.

1) victim_oracle 이벤트 (가장 강한 증거)  
2) canary token 노출 (`ORACLE_TOKEN`)  
3) OAST callback (`victims/paper-victim` + OAST 라우팅)  
4) 응답 본문 내 직접 아티팩트 패턴  
5) 이 외는 `context_required` 또는 `failed`

`context_required` 패밀리: `idor`, `csrf`, `xss`, `auth_bypass`, `file_upload`  
이 패밀리는 요청/응답 페어만으로 확정이 어려워 브라우저/세션/오라클 연동 증거가 필요합니다.

### 2.3 평가 품질 통제

- 공격 결과를 오라클 우선으로 판단해 오탐/과대 확증을 줄임
- 브라우저 하네스 로그가 누락될 경우, 세션 유효성 검사에서 경고 발생
- 매 세션 `analysis/session_validation.json`로 매핑/라벨/산출물 상태를 점검

---

## 3) 구조 및 주요 파일

- `victims/paper-victim/ground_truth_manifest.json`
  - GT 매핑, oracle 타입, WSTG/CAPEC 근거, reference 링크
- `victims/paper-victim/app.py`
  - 10개 공격 케이스의 검증 엔드포인트
- `scripts/classify_attacks.py`
  - 요청 로그 기반 라벨링( paper-victim 모드 지원 )
- `scripts/verify_success.py`
  - oracle + response artifact 기반 성공 판정 엔진
- `scripts/response_heuristics.py`
- `scripts/collect_paper_victim_gt_evidence.py`
  - rule별 시도/성공 집계 및 per-rule evidence 산출
- `scripts/session_validation.py`
  - 세션 품질 점검기(매핑 누락, log 누락, out-of-scope 비율 등)
- `docs/01_EXPERIMENT_GUIDE.md`
  - 실험 진행 순서와 산출물 해석
- `docs/references.bib`
  - 선행 연구/표준 인용 출처(OWASP WSTG, OWASP Benchmark, CRS, TestREx 등)
- `docker-compose.yml`
  - victim-only 네트워크, OAST, browser 하네스 구성
- `metrics/oast_server.py`, `metrics/browser_harness.py`
  - blind 시나리오 및 클라이언트 실행 검증 장치
- `docs/00_HANDOFF.md`
  - 다음 세션을 위한 설계/점검 핸드오프

---

## 4) 실행 (빠른 시작)

1) 환경 변수 설정

```bash
cp .env.example .env
```

2) 의존 컨테이너 실행 포함 전체 파이프라인

```bash
chmod +x run.sh
./run.sh --prompt prompts/attack.txt --all --victim paper-victim --mode struct
```

3) 세션 유효성 점검

```bash
python scripts/session_validation.py results/<SESSION_ID> --victim paper-victim
```

4) GT evidence 및 취약점 결과 확인

```bash
python scripts/collect_paper_victim_gt_evidence.py results/<SESSION_ID> \
  --output-json results/<SESSION_ID>/analysis/paper_victim_ground_truth_evidence.json \
  --output-markdown results/<SESSION_ID>/analysis/paper_victim_ground_truth_evidence.md

ls results/<SESSION_ID>/analysis
```

---

## 5) 결과물 해석 체크리스트 (각 세션 필수)

- `results/<session>/analysis/session_validation.json`
  - `validation_checks.count == 0`(또는 새 포맷의 경고 없음)
  - `attack_label_audit.totals.missing_rule_id == 0`
  - `attack_label_audit.totals.unmapped_rule_id == 0`
  - `paper_victim_browser_log_missing` 경고 없음
- `results/<session>/analysis/paper_victim_ground_truth_evidence.json`
  - `present == true`
- `results/<session>/analysis/vulnerability_results.json`
  - `by_rule[*].oracle_type`이 `paper_victim_*` 규약과 정합

---

## 6) 왜 이 구조가 맞는가

이 프로젝트는 다음 원칙으로 "사견 기반 성공 판정"을 제거합니다.

- WSTG의 검증 지침(재현 가능하고 직접 증거 기반)에 따른 판정 우선순위
- OWASP Benchmark/TestREx 계열의 GT 중심 실험 철학 반영
- CRS anomaly scoring은 공격 후보 필터링 도구로만 사용(최종 판정은 oracle/G T 중심)
- 논문의 계량 지표(ASR, confirmed, context_required)를 GT와 정합되게 계산

---

## 7) 선행근거

- OWASP WSTG
- OWASP CRS Anomaly Scoring
- OWASP Benchmark
- NIST SP 800-115
- TestREx
- AutoPenBench
- TermiBench

상세 bibtex는 `docs/references.bib`를 사용하세요.

---

## 8) 후속 작업

다음 세션에서 바로 이어 할 일:

1. 위 4개 체크포인트를 충족한 새 세션 1회 생성
2. `docs/00_HANDOFF.md`에 `analysis/*` 핵심 지표 수치 갱신
3. 논문/리포트 표기용으로 `results/<session>/analysis/paper_victim_ground_truth_evidence.md` 사용
