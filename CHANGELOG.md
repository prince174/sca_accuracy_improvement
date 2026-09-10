# Changelog

## 0.2.0 — 2026-09-10

- добавлен анализ Java JAR/WAR внутри container image без запуска контейнера;
- реализовано сопоставление CycloneDX SBOM с фактическими Maven-компонентами;
- добавлены точные bytecode-ссылки на JVM-методы и база vulnerability rules;
- реализованы CycloneDX VEX, conservative policy gate и schema validation;
- добавлен полный golden Maven/image/VDR сценарий с ожидаемыми решениями;
- добавлен обмен SBOM, VDR и VEX с Dependency-Track;
- добавлены TeamCity pipeline step и ожидание асинхронной обработки BOM;
- добавлены DeepSeek и локальные OpenAI-compatible endpoints;
- добавлен on-prem HTTP-сервис с bearer auth, очередью и сохранением job state;
- добавлен GitHub CI для Python, golden image и сервисного контейнера.
