# Golden Java/Maven fixture

Этот проект создаёт настоящий CycloneDX SBOM и специальный контейнерный образ с
заранее известными расхождениями.

| Maven component | How the image is built | Expected status |
|---|---|---|
| `org.apache.commons:commons-lang3:3.14.0` | Included in Spring Boot fat JAR | `confirmed_present` |
| `commons-codec:commons-codec:1.17.0` | Compile scope, deliberately excluded by the Boot plugin | `unexpected_absent` |
| `jakarta.servlet:jakarta.servlet-api:6.0.0` | Provided scope | `expected_absent` |
| `org.junit.jupiter:junit-jupiter-api:5.10.3` | Test scope | `expected_absent` |
| `org.slf4j:slf4j-api:2.0.13` | Excluded; version 2.0.16 is copied into the image | `version_conflict` |
| `jakarta.activation:jakarta.activation-api:2.1.3` | Copied by the image-libs build, absent from application SBOM | `observed_not_declared` |

Сборка выполняется контейнерным Maven и не требует локальной установки Maven:

```powershell
.\golden\build.ps1

uv run sca-accuracy `
  --sbom golden\app\target\bom.json `
  --dependency-tree golden\app\target\dependency-tree.json `
  --image sca-accuracy-golden:latest `
  --output out\golden `
  --expectations golden\expected-statuses.json `
  --findings golden\findings.vdr.json `
  --vex-mode safe `
  --vulnerability-rules golden\vulnerability-rules.json `
  --vex-expectations golden\expected-vex-states.json
```

`expected-statuses.json` проверяет выбранные контрольные компоненты и завершает
команду с ошибкой при любом отклонении. Полный результат gate записывается в
`expectation-result.json`. Остальные транзитивные зависимости остаются в отчёте.

`findings.vdr.json` содержит три синтетических INTERNAL finding. Правило для
`GOLDEN-2026-0001` указывает точную JVM-сигнатуру `StringUtils.defaultIfBlank`,
которую вызывает приложение, поэтому статус становится `exploitable`.
Неожиданно отсутствующий compile-компонент остаётся `in_triage`, а отсутствующая
test dependency получает `not_affected` с `code_not_present`.

`expected-vex-states.json` превращает эти три решения в воспроизводимый gate.
Отсутствие прямой ссылки на символ не используется для автоматического
`not_affected`.
