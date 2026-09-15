# Универсальный MVP

```mermaid
flowchart LR
  B[Build SBOM] --> R[Package URL reconciliation]
  I[Registry image] --> S[Save immutable image ID]
  S --> C[Syft image catalog]
  C --> R
  G[Source checkout] --> D[Syft source catalog]
  D --> R
  R --> E[Enriched SBOM + assessment + coverage]
  V[Dependency-Track VDR] --> P[Evidence policy]
  R --> P
  P --> X[VEX in_triage]
  E --> L[Optional advisory LLM]
```

Образ не запускается. Checkout даёт декларации, образ — свидетельства поставки.
Maven tree принимается опционально, не генерируется. Scope не универсален.
Package URL нормализуется с сохранением экосистемы и qualifiers; Maven type=jar
нормализуется к умолчанию. Ошибка сканера завершает задание ошибкой.
Syft закреплён в Dockerfile по версии/digest. Исходный JSON сохраняется как evidence.
LLM не меняет статусы. Runtime reachability и условия оригинальной сборки неизвестны.
