# TeamCity integration

Добавьте PowerShell build step после сборки и push образа. Агент должен иметь
Python 3.11+, `uv`, Syft 1.51.1, Docker CLI и доступ к registry. Docker login к Nexus
выполняется штатным секретным шагом pipeline до запуска интеграции.

```powershell
.\integrations\teamcity.ps1 `
  -ProjectUuid "%env.DEPENDENCY_TRACK_PROJECT_UUID%" `
  -Image "%env.IMAGE_REPOSITORY%:%build.number%" `
  -Sbom "target\bom.json" `
  -Source "." `
  -VulnerabilityRules "security\vulnerability-rules.json" `
  -Output "sca-accuracy-out"
```

Секретные TeamCity parameters:

- `env.DEPENDENCY_TRACK_API_KEY`;
- `env.DEEPSEEK_API_KEY`, только если передан `-WithLlm`.

Обычные environment parameters:

- `env.DEPENDENCY_TRACK_URL`;
- `env.DEPENDENCY_TRACK_PROJECT_UUID`;
- `env.IMAGE_REPOSITORY`.

Скрипт загружает исходный SBOM, ждёт завершения обработки, экспортирует VDR,
анализирует локальный образ, загружает enriched SBOM, снова ждёт обработки и затем
применяет VEX. Отчёты публикуются как TeamCity artifact `sca-accuracy.zip`.

Если `-DependencyTree` не передан, анализатор сам вызывает закреплённую версию
`maven-dependency-plugin:tree` в каталоге `-Source`. Для multi-module проекта
передавайте checkout соответствующего commit; сборщики не запускаются.
