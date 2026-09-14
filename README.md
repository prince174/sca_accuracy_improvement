# SCA Accuracy Improvement

[![CI](https://github.com/prince174/sca_accuracy_improvement/actions/workflows/ci.yml/badge.svg)](https://github.com/prince174/sca_accuracy_improvement/actions/workflows/ci.yml)

Прототип сопоставляет CycloneDX SBOM Maven-проекта с Java-компонентами, которые
фактически попали в контейнерный образ. Результат привязан к digest образа, даже
если входом был изменяемый тег вроде `image:latest`.

Фактический входной контракт соответствует build pipeline:

- `sbom.json` из артефактов Maven-сборки;
- имя образа, который анализатор самостоятельно получает из registry с `--pull`;
- checkout исходного кода на том же commit, что и сборка.

`dependency-tree.json` не является обязательным артефактом. Если он не передан,
анализатор создаёт его из checkout исходников через закреплённый
`maven-dependency-plugin:3.11.0`. VDR также не требуется получать из TeamCity:
end-to-end step сам выгружает его из проекта Dependency-Track после обработки
исходного SBOM.

Первая версия умеет:

- прочитать слои сохранённого Docker-образа без создания и запуска контейнера;
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
контейнера не создаётся и не запускается: сервис выполняет `docker image save` и
читает слои образа с учётом overlay whiteouts.

Состояние каждого задания сохраняется рядом с результатами в `job.json`.
Завершённые задания доступны после рестарта сервиса; прерванные помечаются как
`failed` с явной причиной.

```powershell
New-Item -ItemType Directory -Force workspace | Out-Null
Copy-Item G:\path\to\bom.json workspace\bom.json
$env:SCA_API_TOKEN = "replace-with-a-secret"
docker compose up --build -d

$headers = @{ Authorization = "Bearer $env:SCA_API_TOKEN" }
$body = @{
  sbom_path = "bom.json"
  source_path = "source"
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

Для private Nexus Docker CLI внутри сервиса должен получить registry credentials
через секретно смонтированный Docker `config.json`. Корпоративный Maven
`settings.xml` с mirror/credentials аналогично монтируется в `/root/.m2`; named
volume `maven-cache` сохраняет уже загруженные зависимости.

## Быстрый запуск

Нужны Python 3.11+, `uv` и Docker с локально доступным образом.

```powershell
cd G:\code\SCA_accuracy_improvement
uv sync --extra dev
uv run sca-accuracy `
  --sbom G:\path\to\bom.json `
  --image image:latest `
  --output out `
  --source G:\path\to\source `
  --pull
```

`--source` должен указывать на Maven-модуль с `pom.xml`, которому соответствует
SBOM. Для уже подготовленного дерева вместо него можно передать
`--dependency-tree`. Генерация Maven evidence выполняет Maven над доверенным
checkout проекта и может обращаться к настроенным корпоративным репозиториям.

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

Для OpenAI-compatible локальной модели укажите loopback URL и имя модели. Ключ для
`localhost`, `127.0.0.1` и `::1` необязателен; для любого удалённого endpoint нужен
`SCA_LLM_API_KEY` или `DEEPSEEK_API_KEY`.

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
