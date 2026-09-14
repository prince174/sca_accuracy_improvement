# Security

## Секреты

Передавайте ключи только через environment variables или secret storage CI.
Не добавляйте `.env`, API keys и registry credentials в репозиторий или артефакты.
`DEEPSEEK_API_KEY`, `SCA_LLM_API_KEY`, `DEPENDENCY_TRACK_API_KEY` и
`SCA_API_TOKEN` не должны попадать в параметры командной строки.

## Доверительная граница

Container images, SBOM, VDR и vulnerability rules считаются недоверенными
входными данными. Анализатор не запускает entrypoint образа. On-prem сервису нужен
доступ к Docker socket; разворачивайте его на выделенном runner/host в доверенной
сети и ограничивайте доступ bearer token и сетевой политикой.

Автоматическое получение Maven scope запускает Maven над переданным checkout.
Передавайте только доверенный исходный код компании: Maven extensions и плагины
являются исполняемым кодом. Registry и Maven credentials должны быть настроены на
runner/host и не передаваться в JSON задания.

LLM получает только структурированное резюме расхождений и findings. Внешний вызов
выполняется только с `--with-llm`. Ответ модели не может автоматически подавить
finding.

## Сообщение об уязвимости

Не публикуйте сведения об уязвимости в открытом issue. Используйте GitHub Private
Vulnerability Reporting в разделе Security репозитория. Укажите версию, входные
данные без секретов, ожидаемое и фактическое поведение.
