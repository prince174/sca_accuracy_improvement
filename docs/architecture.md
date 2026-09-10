# Архитектура продуктового контура

```text
TeamCity build
  ├── CycloneDX bom.json
  └── image reference
          │
          ▼
Evidence collectors ──► normalized evidence store
  image/JAR metadata           │
  hashes/locations             ├──► deterministic reconciliation
  later: call graph            │           │
                               │           ▼
                               └──► LLM evidence analyst
                                           │ advisory JSON
                                           ▼
                                  policy and evidence gate
                                      │             │
                              enriched SBOM     CycloneDX VEX
                                      └──────┬──────┘
                                             ▼
                                      Dependency-Track
```

## Контракты

Анализ относится к неизменяемому digest образа. Тег используется только для
разрешения digest в начале задания. Каждый факт хранит источник, расположение и
уровень уверенности.

Модель получает JSON с ограниченным набором фактов. Она не получает credentials,
полный исходный код или бинарные файлы. Её ответ проходит синтаксическую проверку
и сохраняется отдельно от детерминированного результата.

Policy gate в MVP запрещает модели подавлять finding. В будущем автоматический
VEX-вердикт допускается только тогда, когда правило для конкретного класса
уязвимости может проверить все обязательные условия. Неизвестность сохраняет
finding открытым.

## Переход с DeepSeek API на on-premise

Интеграция использует OpenAI-compatible endpoint и четыре параметра: URL, model ID,
API key и timeout. Для on-premise достаточно изменить `SCA_LLM_BASE_URL`,
`SCA_LLM_MODEL` и при необходимости `SCA_LLM_API_KEY`. Loopback endpoint может
работать без ключа. Форматы evidence, assessment и policy gate остаются прежними.
Перед переключением обе модели прогоняются на закреплённом наборе вручную
размеченных сборок и findings.

## Доверительная граница

Образы считаются недоверенными. Контейнер не запускается; `docker create` только
создаёт файловое представление, после чего `docker export` выдаёт объединённую
rootfs. Архив не распаковывается на хост. ZIP/JAR читаются с ограничением размера.

При использовании внешнего DeepSeek API метаданные расхождений покидают локальный
контур. Это должно быть явно включено флагом `--with-llm`. Без флага весь анализ
локальный и детерминированный.
