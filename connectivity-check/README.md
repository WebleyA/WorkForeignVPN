# Проверка доступности сервисов

Самостоятельная локальная веб-страница с Python-сервером. Нужен Docker либо Python 3.9+; дополнительные Python-пакеты не требуются.

Проверяет:

- `77.88.55.88:80` — российский сервис Яндекс: HTTP напрямую по IP с заголовком `Host: yandex.ru`.
- `142.251.13.113:443` — Google: HTTPS напрямую по IP с `Host` и TLS SNI `google.com`, с проверкой сертификата.

IP заданы статически; если сервис изменит адрес, его нужно обновить в `server.py` и `index.html`. В этих двух проверках не вызывается системный DNS-резолвер и не выполняются перенаправления. Ответ HTTP 301/302 подтверждает доступность исходного IP; доступность адреса перенаправления не проверяется.

- `yandex.ru:443`, `google.com:443`, `lk.big3.ru:443` — HTTPS и ответ HTTP.
- После Google — две карточки внешнего IP: `https://api.ipgeo.ru/` (IP и страна) и `https://api.ipify.org/?format=json` (IP). Адреса определяются заново при каждой проверке через сеть контейнера. Российский и зарубежный сервисы могут увидеть разные IP при раздельной маршрутизации VPN; расположение сервиса само по себе не гарантирует страну выходного IP.
- `api.openai.com:443`, путь `/v1/models` — запрос без API-ключа. `401 Unauthorized` подтверждает сетевую доступность; права аккаунта и доступ к моделям не проверяются.
- `api.anthropic.com:443`, путь `/v1/models` — Claude API без ключа; `401 Unauthorized` также подтверждает сетевую доступность.
- `10.10.13.98:5432` — TCP и ответ PostgreSQL на SSLRequest без авторизации и запросов к базе. Общий таймаут — 2 секунды.

HTTP 403 отображается красным. Время в карточке — продолжительность проверки, а не ICMP ping. Результаты не сохраняются.

## Локальный Docker-образ

Из корня проекта:

```bash
docker build -t connectivity-check:latest ./connectivity-check
docker run --rm -d --name connectivity-check -p 127.0.0.1:8765:8765 connectivity-check:latest
open http://127.0.0.1:8765/
```

Последняя команда открывает браузер на macOS. Docker сам браузер хост-системы не открывает. На других ОС открой этот адрес вручную.

Порт опубликован только на `127.0.0.1`. Для другого локального порта поменяй левую часть публикации: `-p 127.0.0.1:8766:8765`, затем открой `http://127.0.0.1:8766/`.

Остановка:

```bash
docker stop connectivity-check
```

Контейнер автоматически удалится благодаря `--rm`. Для запуска в текущем терминале убери `-d`; остановка — Ctrl+C.

## Публикация и запуск скачанного образа

### GHCR

Имя образа для аккаунта WebleyA: `ghcr.io/webleya/connectivity-check:latest`.

Создай GitHub personal access token **classic** с правом `write:packages` и выполни вход в своём терминале. В поле Password вводится токен, а не пароль GitHub:

```bash
docker login ghcr.io -u WebleyA
```

Для сборки под Apple Silicon и Intel создай отдельный сборщик один раз, затем опубликуй образ из корня проекта:

```bash
docker buildx create --name connectivity-check-ghcr --driver docker-container
docker buildx build --builder connectivity-check-ghcr --platform linux/arm64,linux/amd64 -t ghcr.io/webleya/connectivity-check:latest --push ./connectivity-check
```

Если сборщик уже существует, первую команду повторять не нужно. После первой загрузки открой пакет `connectivity-check` в GitHub → Packages → Package settings → Change visibility → Public. Новые пакеты GHCR по умолчанию приватные; публичный пакет можно скачивать без входа.

Запуск опубликованного образа на macOS:

```bash
docker run --rm -d --name connectivity-check --pull always -p 127.0.0.1:8765:8765 ghcr.io/webleya/connectivity-check:latest
open http://127.0.0.1:8765/
```

Документация: [GHCR: авторизация и публикация](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

### Docker Hub

В примерах замени `YOUR_DOCKERHUB_USER/connectivity-check:latest` на адрес своего образа Docker Hub. Создай публичный репозиторий `connectivity-check` в своём аккаунте. Для Apple Silicon и Intel можно опубликовать обе архитектуры одной сборкой:

```bash
docker buildx build --platform linux/arm64,linux/amd64 -t YOUR_DOCKERHUB_USER/connectivity-check:latest --push ./connectivity-check
```

При необходимости заранее выполни `docker login` для своего реестра. Сборка с `--push` публикует образ, локальная загрузка образа выполняется при запуске.

Команды, которые можно отправить пользователю macOS:

```bash
docker run --rm -d --name connectivity-check --pull always -p 127.0.0.1:8765:8765 YOUR_DOCKERHUB_USER/connectivity-check:latest
open http://127.0.0.1:8765/
```

Docker Desktop должен быть запущен. Если контейнер с таким именем уже работает, сначала останови его.

## Сеть и VPN

Проверки выполняются там, где работает контейнер. На Mac Docker Desktop направляет исходящие подключения через свой процесс на хосте; результат зависит от сетевых настроек и VPN для Docker Desktop. Прокси только в браузере на проверки не влияет. Проверь доступ к рабочей сети именно из контейнера: успех запуска страницы не означает доступность `10.10.13.98`.

Документация: [сеть Docker Desktop](https://docs.docker.com/desktop/features/networking/), [сборка для нескольких архитектур](https://docs.docker.com/build/building/multi-platform/).

## Запуск без Docker

Из корня проекта:

```bash
python3 connectivity-check/server.py
open http://127.0.0.1:8765/
```

Остановка — Ctrl+C. Порт можно задать через `--port 8766`.

`index.html` можно открыть как файл при сервере, запущенном на порту `8765`. Обычный статический сервер не реализует API проверок.

## Проверки кода

```bash
python3 -m unittest discover -s connectivity-check -p 'test_*.py'
```

Образ содержит только `server.py` и `index.html` из этого каталога. Исходники других компонентов проекта, тесты и локальные настройки в него не копируются.
