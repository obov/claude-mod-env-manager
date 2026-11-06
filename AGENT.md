# AGENT.md

Claude Code mod `env-manager`, 배포 경로: GitHub `obov/claude-mod-env-manager` 마켓플레이스 → 로컬 설치 `env-manager@claude-mod-env-manager` (user scope).

## 개선 후 항상 수행 (묻지 말고 끝까지)

모든 개선 작업은 검증 → 버전 업 → 커밋 → 푸시 → 로컬 반영까지가 한 단위다.

1. 검증
   - `claude plugin validate .` (아이콘 경고만 허용)
   - `claude plugin test .` 전체 통과
   - 타입 체크: `.claude-plugin/types/`가 없으면 스킬 types 파일을 include한 임시 tsconfig로 `tsc -p`
2. 버전 업: `.claude-plugin/plugin.json`의 `version` 올림 (기능 추가 minor, 수정 patch). 안 올리면 `plugin update`가 변경을 못 잡을 수 있음
3. 커밋: `main`에 직접, 메시지는 영어 한 줄 요약. 공동 작성자(Co-Authored-By) 줄 넣지 않음
4. 푸시: `git push origin main`
5. 로컬 반영:
   ```sh
   claude plugin marketplace update claude-mod-env-manager
   claude plugin update env-manager@claude-mod-env-manager
   ```
   반영은 Claude Code 재시작 후 적용

## 코드 규칙

- `$.state` atom 값의 형태가 바뀌면 `shape` 문자열을 올림 (`ui-6` → `ui-7`), 계약은 `types/index.d.ts`
- 사용자 UI 문구는 한국어, 짧은 명사형
- 안내창(dialog)은 별도 pane이 아닌 env 패널 안 overlay 카드 (`position="absolute"` Box, `dialogAtom`). 열려 있는 동안 트리 키 입력 무시
- 테스트에서 `$.ui.open` / `$.ui.close`는 `{ value: ... }`로 stub
