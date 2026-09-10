# SCA Accuracy Improvement

Прототип сопоставляет CycloneDX SBOM Maven-проекта с Java-компонентами, которые
фактически попали в контейнерный образ. Результат привязан к digest образа, даже
если входом был изменяемый тег вроде `image:latest`.

Первая версия умеет:

- безопасно создать, но не запускать контейнер, и экспортировать его rootfs;
- найти JAR/WAR и вложенные библиотеки Spring Boot (`BOOT-INF/lib`) и WAR (`WEB-INF/lib`);
- извлечь Maven coordinates из `META-INF/maven/**/pom.properties` и вычислить SHA-256;
- сопоставить наблюдения с компонентами CycloneDX по точным Maven coordinates;
- сформировать `inventory.json`, `assessment.json` и `sbom.enriched.json`;
- опционально передать только структурированные расхождения в DeepSeek для объяснения.

LLM не читает бинарный образ и не принимает решения о подавлении уязвимостей. Она
формирует гипотезы и список недостающих доказательств. Такой интерфейс позже можно
переключить на локальную модель без изменения анализаторов.

## Быстрый запуск

Нужны Python 3.11+, `uv` и Docker с локально доступным образом.

```powershell
cd G:\code\SCA_accuracy_improvement
uv sync --extra dev
uv run sca-accuracy `
  --sbom G:\path\to\bom.json `
  --image image:latest `
  --output out
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
  --with-llm
```

## Выходные данные

- `inventory.json` — все наблюдённые компоненты, их расположение, источник
  идентификации, хеш и уверенность метода.
- `assessment.json` — `confirmed`, `sbom_only`, `observed_only` и
  `version_conflict`, плюс консультативный вывод модели.
- `sbom.enriched.json` — исходный BOM с digest образа, статусами сопоставления и
  CycloneDX evidence occurrences. Компоненты не удаляются автоматически.
- `report.html` — автономный человекочитаемый отчёт без внешних ресурсов.

## Границы MVP

Прототип подтверждает состав Java-приложения, но пока не строит call graph, не
исследует конфигурацию production и не выпускает автоматические `NOT_AFFECTED`.
Filename fallback имеет низкую уверенность и не считается точным доказательством.
Системные пакеты базового образа пока не анализируются.

Следующий вертикальный срез: импорт findings Dependency-Track, база условий CVE,
статический call graph Java и генерация CycloneDX VEX с машинно проверяемыми
основаниями.
