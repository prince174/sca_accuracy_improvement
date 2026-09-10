# TeamCity integration

Добавьте PowerShell build step после сборки и push образа. Агент должен иметь
Python 3.11+, `uv`, Docker CLI и доступ к собранному образу.

```powershell
.\integrations\teamcity.ps1 `
  -ProjectUuid "%env.DEPENDENCY_TRACK_PROJECT_UUID%" `
  -Image "%env.IMAGE_REPOSITORY%:%build.number%" `
  -Sbom "target\bom.json" `
  -DependencyTree "target\dependency-tree.json" `
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
