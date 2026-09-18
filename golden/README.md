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

```bash
uv run python golden/build.py
uv run sca-accuracy \
  --sbom golden/app/target/bom.json \
  --dependency-tree golden/app/target/dependency-tree.json \
  --image sca-accuracy-golden:latest \
  --output out/golden \
  --expectations golden/expected-statuses.json \
  --findings golden/findings.vdr.json \
  --vex-mode safe \
  --vulnerability-rules golden/vulnerability-rules.json \
  --vex-expectations golden/expected-vex-states.json
```

`expected-statuses.json` проверяет выбранные контрольные компоненты и завершает
команду с ошибкой при любом отклонении. Полный результат gate записывается в
`expectation-result.json`. Остальные транзитивные зависимости остаются в отчёте.

`findings.vdr.json` содержит три синтетических INTERNAL finding. Правило для
`GOLDEN-2026-0001` указывает JVM-сигнатуру `StringUtils.defaultIfBlank`.
Прямая ссылка на этот метод обнаруживается, но не доказывает эксплуатацию.
Все три finding остаются `in_triage`, включая не обнаруженную test dependency.
`expected-vex-states.json` проверяет именно эту консервативную policy.

В golden сборочные контейнеры Maven запускаются для создания тестовых артефактов.
Исследуемый образ приложения во время анализа не запускается.
Это локальная тестовая обвязка, а не обязательный шаг production-сервиса.
