# Вызов сервиса из build pipeline

Интеграция использует HTTP API v2 и не зависит от операционной системы build runner.
Сервис разворачивается на Linux и сам получает входные данные по ссылкам.

После публикации артефактов и push образов вызывающая система формирует JSON:

- HTTPS clone URL Bitbucket;
- полный hash исходного commit;
- группы `targets`: имя, прямая ссылка на SBOM конкретного TeamCity build ID,
  список относящихся к нему Docker references из Nexus;
- необязательный `with_llm`, по умолчанию false.

Готовое тело запроса: [remote-request.json](../examples/remote-request.json).
Одна группа может иметь несколько образов. Разные SBOM оформляются разными группами.
Одно задание относится к одному репозиторию и commit.

## Последовательность

1. `POST /v2/analyses` с Bearer token → сохранить `id`.
2. Опрос `GET /v2/analyses/<id>` до `succeeded` или `failed`.
3. При `failed` завершить внешний шаг ошибкой и сохранить поле `error`.
4. При `succeeded` пройти по `result.targets`; для каждого результата скачать
   `/v2/analyses/<id>/<sbom_artifact>`.
5. Внешняя интеграция загружает полученные SBOM в выбранные проекты Dependency-Track.

Сервис не создаёт проекты Dependency-Track, не выбирает их UUID и не загружает туда
BOM автоматически. Соответствие `target_id → project/version` хранит вызывающая система.

Для TeamCity используйте прямую ссылку на содержимое артефакта:
`https://teamcity.xxx/app/rest/builds/id:12345/artifacts/content/path/sbom.json`.
Страница билда, redirects и подписанные URL с query-параметрами не поддерживаются.
Для Nexus нужен Docker registry reference, например `nexus.xxx/team/app:build-12345`,
а не ссылка на экран Browse. Предпочтительно использовать immutable digest.
Для Bitbucket нужен HTTPS clone URL, не ссылка на страницу commit.

Credentials TeamCity, Bitbucket и Nexus настраиваются на стороне сервиса.
Их нельзя помещать в JSON задания. Контракт, curl-примеры, параметры Linux Compose
и ограничения описаны в [README](../README.md).
