# SCA Accuracy Improvement

[![CI](https://github.com/prince174/sca_accuracy_improvement/actions/workflows/ci.yml/badge.svg)](https://github.com/prince174/sca_accuracy_improvement/actions/workflows/ci.yml)

Прототип сопоставляет CycloneDX SBOM Maven-проекта с Java-компонентами, которые
фактически попали в контейнерный образ. Результат привязан к digest образа, даже
если входом был изменяемый тег вроде `image:latest`.

Первая версия умеет:

- безопасно создать, но не запускать контейнер, и экспортировать его rootfs;
- найти JAR/WAR и вложенные библиотеки Spring Boot (`BOOT-INF/lib`) и WAR (`WEB-INF/lib`);
- извлечь Maven coordinates из `META-INF/maven/**/pom.properties` и вычислить SHA-256;
- извлечь ссылки на методы библиотек из JVM constant pool классов приложения;
- сопоставить наблюдения с компонентами CycloneDX по точным Maven coordinates;
- сформировать `inventory.json`, `assessment.json` и `sbom.enriched.json`;
- принять CycloneDX VDR/BOM с findings и сформировать валидный CycloneDX VEX;
- сопоставить finding с точной JVM-сигнатурой из проверяемой базы правил;
- опционально передать только структурированные расхождения в DeepSeek для объяснения.

LLM не читает бинарный образ и не принимает решения о подавлении уязвимостей. Она
формирует гипотезы и список недостающих доказательств. Такой интерфейс позже можно
переключить на локальную модель без изменения анализаторов.

## On-prem сервис

HTTP API запускает анализы в ограниченной очереди. Входные файлы читаются только
из каталога `SCA_WORKSPACE`, результаты сохраняются в `results/<job-id>`. Образ
контейнера не запускается: сервис создаёт остановленный контейнер и экспортирует
его файловую систему через Docker API/CLI.

```powershell
New-Item -ItemType Directory -Force workspace | Out-Null
Copy-Item G:\path\to\bom.json workspace\bom.json
$env:SCA_API_TOKEN = "replace-with-a-secret"
docker compose up --build -d

$headers = @{ Authorization = "Bearer $env:SCA_API_TOKEN" }
$body = @{
  sbom_path = "bom.json"
  image = "image:latest"
  vex_mode = "safe"
} | ConvertTo-Json
$job = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/analyses `
  -Headers $headers -ContentType application/json -Body $body
Invoke-RestMethod -Uri "http://127.0.0.1:8080/v1/analyses/$($job.id)" -Headers $headers
```

Доступны `GET /health`, защищённый `GET /ready`, создание задания через
`POST /v1/analyses`, чтение состояния и скачивание разрешённых артефактов. Для
анализа локальных образов compose монтирует Docker socket. В Linux доступ к этому
socket равнозначен административному доступу к Docker host, поэтому сервис следует
размещать в отдельном доверенном контуре и защищать `SCA_API_TOKEN`.

## Быстрый запуск

Нужны Python 3.11+, `uv` и Docker с локально доступным образом.

```powershell
cd G:\code\SCA_accuracy_improvement
uv sync --extra dev
uv run sca-accuracy `
  --sbom G:\path\to\bom.json `
  --image image:latest `
  --output out `
  --dependency-tree G:\path\to\dependency-tree.json
```

Для анализа расхождений через DeepSeek задайте переменные окружения. Значения по
умолчанию совпадают с конфигурацией Altron; `.env` автоматически не читается, чтобы
секрет нельзя было случайно подобрать из соседнего проекта.

```powershell
$env:DEEPSEEK_API_KEY = "..."
$env:SCA_LLM_BASE_URL = "https://api.deepseek.com/v1"
$env:SCA_LLM_MODEL = "deepseek-v4-flash"

uv run sca-accuracy `
  --sbom G:\path\to\bom.json `
  --image image:latest `
  --output out `
  --findings G:\path\to\findings.vdr.json `
  --vex-mode safe `
  --with-llm
```

## Выходные данные

- `inventory.json` — все наблюдённые компоненты, их расположение, источник
  идентификации, хеш, уверенность метода и наблюдённые bytecode symbols.
- `assessment.json` — `confirmed`, `sbom_only`, `observed_only` и
  `version_conflict`, плюс консультативный вывод модели.
- `sbom.enriched.json` — исходный BOM с digest образа, статусами сопоставления и
  CycloneDX evidence occurrences. Компоненты не удаляются автоматически.
- `report.html` — автономный человекочитаемый отчёт без внешних ресурсов.
- `vulnerability-assessment.json` — решения policy gate и основания автоматизации.
- `vex.json` — CycloneDX VEX для применения решений к существующим findings.

`--vex-mode advisory` оставляет все findings в `in_triage`. Режим `safe`
автоматически ставит `not_affected` отсутствующей Maven test dependency и
`exploitable`, когда приложение содержит точную bytecode-ссылку на JVM-сигнатуру,
заданную для finding в `--vulnerability-rules`. Для остальных случаев VEX остаётся
`in_triage`.

```powershell
uv run sca-accuracy `
  --sbom golden\app\target\bom.json `
  --image sca-accuracy-golden:latest `
  --output out\golden `
  --findings golden\findings.vdr.json `
  --vex-mode safe `
  --vulnerability-rules golden\vulnerability-rules.json `
  --vex-expectations golden\expected-vex-states.json
```

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

## Границы MVP

Прототип подтверждает состав Java-приложения, но пока не строит полный call graph
и не исследует конфигурацию production. Автоматический `NOT_AFFECTED` ограничен
отсутствующими test dependencies.

`bytecode_referenced` означает, что класс приложения содержит прямую JVM-ссылку
на метод компонента. `present_no_reference_observed` означает только отсутствие
такой прямой ссылки; это не доказательство недостижимости из-за транзитивных
вызовов, reflection, dependency injection и динамической загрузки.
Filename fallback имеет низкую уверенность и не считается точным доказательством.
Системные пакеты базового образа пока не анализируются.

Формат базы правил показан в `golden/vulnerability-rules.json`. Каждое правило
связывает идентификатор уязвимости, Maven GAV и одну или несколько полных JVM
сигнатур. Источник и версия такой базы должны контролироваться отдельно от модели.
