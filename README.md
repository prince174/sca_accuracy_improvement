# SCA Accuracy Improvement

Универсальный MVP: CycloneDX SBOM + образ + checkout соответствующего commit.
Целевой контейнер не создаётся и не запускается. Syft 1.51.1 каталогизирует
образ и исходники, общее ядро сопоставляет компоненты по Package URL.
Изменяемый тег закрепляется по local image ID перед сохранением образа.

## Поддержка и ограничения

| Экосистема | Свидетельства |
|---|---|
| Java / Maven / Gradle | JAR/WAR, Maven metadata, JVM static references |
| JavaScript / TypeScript | npm package metadata, поддерживаемые lockfiles |
| Python | dist-info/egg-info, requirements, поддерживаемые lockfiles |
| .NET | NuGet metadata, deps.json, поддерживаемые project/lockfiles |
| Go | build info в бинарниках, go.mod |
| Rust | Cargo.lock, поддерживаемые auditable binaries |
| PHP / Ruby | Composer installed/lock, gemspec/Gemfile.lock |
| Системные пакеты | APK, DEB, RPM databases |

Поддержка конкретных форматов определяется закреплённой версией Syft:
[список каталогизаторов](https://oss.anchore.com/docs/capabilities/all-packages/).
Универсальность интерфейса не гарантирует обнаружение каждой зависимости.
Bundling, shading, vendoring и stripped binaries могут скрывать идентификаторы.

Исходники сканируются без запуска Maven/npm/сборщиков и установки зависимостей.
`dependency-tree.json` — только дополнительное Maven evidence; автоматически
больше не создаётся. Каталог исходников не воспроизводит условия исходного билда.

`confirmed_present` — найдено совпадающее package metadata;
`version_conflict` — найдена другая версия; `observed_not_declared` — пакет образа
не указан в SBOM; `unexpected_absent` — пакет не обнаружен, отсутствие не доказано;
`expected_absent` — ожидание по отдельно переданному Maven scope;
`identity_uncertain` — недостаточная идентификация.

Исходные компоненты не удаляются. Обе настройки `--vex-mode` оставляют findings
в `in_triage`: scope, отсутствие обнаружения и static references не доказывают
`not_affected` или `exploitable`. Runtime reachability MVP не определяет.

## Запуск

Нужны Python 3.11+, uv, Docker CLI и Syft 1.51.1; образ сервиса содержит Syft.
Для нестандартного пути к бинарнику задайте `SCA_SYFT_BINARY`.

```powershell
uv sync --extra dev
uv run sca-accuracy --sbom build/sbom.json --image image:latest --pull --source checkout --output out/analysis
```

Локальное сканирование не требует внешнего API. `--pull` обращается к registry.
Проверка обновлений Syft и Java network enrichment отключены.
Конфигурация сканера из анализируемого checkout не загружается.

Опциональная модель: `--with-llm`, `DEEPSEEK_API_KEY`,
`SCA_LLM_BASE_URL=https://api.deepseek.com/v1`, `SCA_LLM_MODEL=deepseek-v4-flash`.
Модель получает структурированные результаты, только объясняет их.
Для on-prem укажите локальный OpenAI-compatible endpoint. `.env` не читается автоматически.

## Результаты

- `assessment.json`, `report.html`: сравнение с образом и ограничения.
- `inventory.json`: наблюдения и расположение пакетов.
- `source-assessment.json`: отдельное сравнение с каталогом исходников.
- `coverage.json`: сканер, наблюдённые типы пакетов, ограничения анализа.
- `evidence/image.syft.json`, `evidence/source.syft.json`: исходные доказательства.
- `sbom.enriched.json`: исходный BOM с аннотациями и дополнительными пакетами.
- `vex.json`, `vulnerability-assessment.json`: при наличии findings.

## Сервис

```powershell
$env:SCA_API_TOKEN = "replace-with-a-secret"
docker compose up --build -d
```

Входы разместите в `workspace`. `POST /v1/analyses` принимает JSON:

```json
{"sbom_path":"sbom.json","source_path":"checkout","image":"image:latest"}
```

Авторизация: `Authorization: Bearer <SCA_API_TOKEN>`.
`GET /v1/analyses/<id>` возвращает состояние,
`GET /v1/analyses/<id>/artifacts/assessment.json` — результат.
`/health` публичный, `/ready` защищённый. Задания сохраняются на диске.
Docker socket даёт административный доступ к хосту: используйте выделенный worker.
Для Nexus смонтируйте Docker credentials в контур сервиса.

## Dependency-Track

Отдельный CLI обменивается документами с существующим проектом Dependency-Track.
Ключ читается из окружения и не попадает в аргументы процесса или отчёты.

```powershell
$env:DEPENDENCY_TRACK_URL = "https://dependency-track.example"
$env:DEPENDENCY_TRACK_API_KEY = "..."

uv run sca-accuracy-dtrack export-vdr `
  --project 37803005-05ff-46c5-9571-9ac7857fd07d `
  --output out\findings.vdr.json

uv run sca-accuracy-dtrack upload-bom `
  --project 37803005-05ff-46c5-9571-9ac7857fd07d `
  --file out\sbom.enriched.json

uv run sca-accuracy-dtrack wait-bom `
  --token 8bb712b3-bb51-42da-8e7e-af3a138c1844 `
  --timeout 600

uv run sca-accuracy-dtrack apply-vex `
  --project 37803005-05ff-46c5-9571-9ac7857fd07d `
  --file out\vex.json
```

Для экспорта нужны права чтения портфеля и уязвимостей. Загрузка SBOM требует
`BOM_UPLOAD`, применение VEX — `VULNERABILITY_ANALYSIS` либо соответствующее право
обновления в Dependency-Track 5. VEX применяется только к уже существующим
findings, поэтому сначала загружается SBOM и завершается анализ, затем применяется
VEX.

Готовый PowerShell step для TeamCity находится в `integrations/teamcity.ps1`. Он
выполняет полный цикл: исходный SBOM → ожидание Dependency-Track → VDR → анализ
образа → enriched SBOM → VEX → TeamCity artifacts.

## Проверки

```powershell
uv run ruff format --check .
uv run ruff check .
uv run pytest -q
uv build
uv run python golden/universal/verify.py
```

Смешанный golden fixture содержит синтетические packaging metadata. Проверяет
6 экосистем образа и 6 экосистем исходников, включая SBOM-only и source-only случаи.
Это проверка распознавания metadata, не эксплуатации. Оригинальный Java golden
отдельно проверяет настоящий Maven/CycloneDX/Spring Boot билд. Оба включены в CI.
