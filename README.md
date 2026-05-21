# Лабораторная работа №13 — Вариант 17 (повышенная сложность)
# Студент: Тараканова Мария
# Группа: 221131
## Многоагентная SIEM-система на основе NATS + Redis + LLM

---

## Содержание

- [Обзор](#обзор)
- [Архитектура](#архитектура)
- [Предварительные требования](#предварительные-требования)
- [Быстрый старт](#быстрый-старт)
- [Запуск по шагам](#запуск-по-шагам)
- [Динамическое масштабирование](#динамическое-масштабирование)
- [Проверка работы](#проверка-работы)
- [Запуск тестов](#запуск-тестов)
- [Структура проекта](#структура-проекта)
- [Описание файлов](#описание-файлов)
- [NATS-топики](#nats-топики)
- [Redis-ключи](#redis-ключи)

---

## Обзор

Система мониторинга безопасности (SIEM) обнаруживает кибератаки в потоке сырых логов и автоматически блокирует угрозы. Реализованы три класса атак: брутфорс SSH, сканирование портов, DDoS.

**Стек:** Go 1.21 (агенты), Python 3.12 (LLM + оркестратор + scaler), NATS (шина сообщений), Redis (состояние), Jaeger (трассировка), Streamlit (дашборд), Docker API (авто-масштабирование).

---

## Архитектура

```
Источник логов
      │
      ▼  logs.raw
┌─────────────┐
│ log-collector│  Go — нормализует сырые строки в JSON-события
│             │  INCR queue:depth при каждом publish
└─────────────┘
      │
      ▼  logs.normalized  (NATS queue group "correlators")
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ correlator-1 │  │ correlator-2 │  │ correlator-N │  ← динамически запускает scaler
│  (compose)   │  │  (scaler)   │  │  (scaler)   │
└─────────────┘  └─────────────┘  └─────────────┘
  DECR queue:depth при каждом receive
      │
      ▼  incidents.new
┌─────────────┐
│  llm-agent   │  Python — выносит вердикт (LLM или rule-based fallback)
└─────────────┘
      │
      ▼  threat.verdict
┌─────────────┐
│   blocker    │  Go — добавляет IP в blocked_ips / rate_limited_ips
└─────────────┘
      │
      ▼  blocking.done

Redis ◄──── все агенты пишут счётчики stats:*
Jaeger ◄─── OpenTelemetry-спаны от всех агентов
Scaler ──── мониторит queue:depth, управляет контейнерами через Docker API
Streamlit ──► читает Redis, показывает дашборд
```

---

## Предварительные требования

| Инструмент | Версия | Где используется |
|---|---|---|
| Docker Desktop | любая свежая | инфраструктура + авто-масштабирование |
| Go | ≥ 1.21 | log-collector, blocker (+ опционально correlator) |
| Python | 3.12 (рекомендуется через WSL Ubuntu) | LLM-агент, оркестратор, дашборд |
| pip / venv | — | Python-зависимости |

> **Windows:** Python 3.14 несовместим с protobuf (opentelemetry). Используйте Python 3.12 через WSL Ubuntu или системный Python 3.12.

---

## Быстрый старт

```bash
# 1. Перейдите в папку проекта
cd siem-lab

# 2. Создайте .env (см. ниже)

# 3. Соберите образ коррелятора и запустите всю инфраструктуру
docker compose -f docker/docker-compose.yml up -d --build
# Поднимет: NATS, Redis, Jaeger, базовый correlator, scaler

# 4. Установите Python-зависимости
python3 -m venv /tmp/siem-venv
/tmp/siem-venv/bin/pip install -r requirements.txt

# 5. Запустите Go-агенты (два отдельных терминала)
go run ./agents/log-collector/main.go
go run ./agents/blocker/main.go

# 6. Запустите LLM-агент
/tmp/siem-venv/bin/python3 -u llm-agent/main.py

# 7. Запустите дашборд
/tmp/siem-venv/bin/streamlit run web/dashboard.py
```

---

## Запуск по шагам

### Шаг 1 — Файл `.env`

Создайте `siem-lab/.env`:

```env
ANTHROPIC_API_KEY=sk-ant-...   # ваш ключ с console.anthropic.com
NATS_URL=nats://localhost:4222
REDIS_URL=redis://localhost:6379
JAEGER_URL=http://localhost:14268/api/traces
LLM_MODEL=claude-sonnet-4-20250514
```

> Без ключа система работает в режиме **rule-based fallback** — LLM-агент принимает решения по встроенным правилам, pipeline не ломается.

### Шаг 2 — Инфраструктура (Docker)

```bash
cd siem-lab

# Первый запуск: --build собирает образ siem-correlator:latest
docker compose -f docker/docker-compose.yml up -d --build

# Повторный запуск (образ уже собран):
docker compose -f docker/docker-compose.yml up -d
```

Сервисы после старта:

| Сервис | Порт | Описание |
|---|---|---|
| NATS | 4222 / 8222 | брокер сообщений / HTTP мониторинг |
| Redis | 6379 | хранилище состояния |
| Jaeger | 16686 / 14268 | UI трассировки / collector |
| correlator | — | базовый экземпляр коррелятора (Go, образ siem-correlator) |
| scaler | — | авто-масштабирование через Docker API |

Все сервисы подключены к именованной сети `siem-network`.

### Шаг 3 — Python-окружение

```bash
python3 -m venv /tmp/siem-venv
/tmp/siem-venv/bin/pip install -r siem-lab/requirements.txt
```

> На Windows используйте WSL Ubuntu с Python 3.12. Установить venv: `sudo apt install python3.12-venv`.

### Шаг 4 — Go-агенты

`log-collector` и `blocker` запускаются вручную. `correlator` уже работает в Docker (базовый экземпляр), scaler при необходимости добавит ещё.

```bash
cd siem-lab
go run ./agents/log-collector/main.go   # терминал 1
go run ./agents/blocker/main.go         # терминал 2
```

### Шаг 5 — LLM-агент

```bash
cd siem-lab
/tmp/siem-venv/bin/python3 -u llm-agent/main.py
```

### Шаг 6 — Дашборд

```bash
cd siem-lab
/tmp/siem-venv/bin/streamlit run web/dashboard.py --server.port 8501
```

Открыть в браузере: http://localhost:8501

### Шаг 7 — Оркестратор (опционально)

```bash
cd siem-lab
/tmp/siem-venv/bin/python3 orchestrator/main.py
```

---

## Динамическое масштабирование

Scaler автоматически управляет количеством экземпляров коррелятора через Docker API.

### Принцип работы

**Метрика глубины очереди `queue:depth`:**
- `log-collector` делает `INCR queue:depth` при каждом publish в `logs.normalized`
- `correlator` делает `DECR queue:depth` при каждом receive из `logs.normalized`
- Положительное значение = сообщения накапливаются быстрее, чем обрабатываются

**Балансировка через NATS queue group:**  
Все экземпляры коррелятора подписаны через `QueueSubscribe("logs.normalized", "correlators")` — NATS автоматически распределяет каждое сообщение ровно одному экземпляру.

**Логика scaler (`scaler/main.py`):**

| Условие | Действие |
|---|---|
| `queue:depth > 10` и динамических < 3 | `docker.containers.run(siem-correlator)` |
| `queue:depth < 3` и динамических > 0 | `container.stop()` + `container.remove()` |

Динамические контейнеры помечены меткой `siem.managed=true`, что позволяет scaler'у отличать их от базового контейнера compose.

### Настройка порогов

Через переменные окружения сервиса `scaler` в `docker-compose.yml`:

```yaml
SCALE_UP_THRESHOLD=10    # глубина очереди для scale up
SCALE_DOWN_THRESHOLD=3   # глубина очереди для scale down
MAX_INSTANCES=3          # максимум дополнительных контейнеров
POLL_INTERVAL=5          # интервал проверки (секунды)
```

### Пример наблюдения масштабирования

```bash
# 1. Посмотреть логи scaler в реальном времени:
docker logs -f docker-scaler-1

# 2. Проверить запущенные контейнеры:
docker ps --filter "label=siem.managed=true"

# 3. Текущая глубина очереди:
docker exec docker-redis-1 redis-cli GET queue:depth

# 4. Статистика scaler из Redis:
docker exec docker-redis-1 redis-cli MGET \
  stats:scaler:queue_depth stats:scaler:instances \
  stats:scaler:scale_up_total stats:scaler:scale_down_total
```

---

## Проверка работы

### Симуляция брутфорс-атаки

```python
# simulate_brute.py
import asyncio, nats

async def run():
    nc = await nats.connect("nats://localhost:4222")
    for i in range(8):
        await nc.publish("logs.raw",
            f"Failed password for root from 5.5.5.5 port 22 attempt {i}".encode())
    await nc.close()

asyncio.run(run())
```

```bash
/tmp/siem-venv/bin/python3 simulate_brute.py
```

### Проверка результата

```bash
# Должен содержать 5.5.5.5
docker exec docker-redis-1 redis-cli SMEMBERS blocked_ips

# Счётчики всех агентов
docker exec docker-redis-1 redis-cli MGET \
  stats:log_collector stats:correlator stats:llm_agent stats:blocker

# Последние инциденты
docker exec docker-redis-1 redis-cli LRANGE incidents:history -3 -1

# IP с rate-limit (MEDIUM угрозы — не попадают в blocked_ips)
docker exec docker-redis-1 redis-cli SMEMBERS rate_limited_ips
```

---

## Запуск тестов

### Go (unit-тесты log-collector)

```bash
cd siem-lab
go test ./agents/log-collector/ -v
```

8 тестов: `auth_failure`, `port_scan`, `ddos`, `normal`, `unknown`, `id`, `raw`, `authentication failure`.

### Python (pytest)

```bash
cd siem-lab
/tmp/siem-venv/bin/python3 -m pytest orchestrator/tests/ -v
```

5 тестов: отправка лога, retry при сбое, исчерпание retry, чтение статистики Redis, нулевые значения при отсутствии ключей.

---

## Структура проекта

```
lab13-var17/
├── README.md
├── WORKPLAN.md                        # план разработки по фазам
└── siem-lab/
    ├── go.mod                         # Go-модуль и зависимости
    ├── go.sum                         # чексуммы Go-зависимостей
    ├── requirements.txt               # Python-зависимости
    ├── pytest.ini                     # конфигурация pytest
    ├── .env                           # переменные окружения (не в git)
    │
    ├── docker/
    │   └── docker-compose.yml         # NATS, Redis, Jaeger, correlator, scaler
    │
    ├── agents/
    │   ├── log-collector/
    │   │   ├── main.go                # агент нормализации логов
    │   │   └── main_test.go           # unit-тесты normalizeLog()
    │   ├── correlator/
    │   │   ├── main.go                # агент корреляции событий
    │   │   ├── auction.go             # механизм аукциона задач
    │   │   └── Dockerfile             # сборка образа siem-correlator:latest
    │   └── blocker/
    │       └── main.go                # агент блокировки угроз
    │
    ├── scaler/
    │   ├── main.py                    # авто-масштабирование через Docker API
    │   └── Dockerfile                 # образ scaler
    │
    ├── llm-agent/
    │   └── main.py                    # LLM-агент вынесения вердиктов
    │
    ├── orchestrator/
    │   ├── main.py                    # Python-оркестратор pipeline
    │   ├── __init__.py
    │   └── tests/
    │       ├── test_orchestrator.py   # pytest-тесты оркестратора
    │       └── __init__.py
    │
    └── web/
        └── dashboard.py               # Streamlit-дашборд
```

---

## Описание файлов

### `docker/docker-compose.yml`

Запускает 5 сервисов в именованной сети `siem-network`:
- **nats** — брокер сообщений, порты 4222 (клиент) и 8222 (HTTP мониторинг)
- **redis** — хранилище состояния (счётчики, заблокированные IP, история инцидентов)
- **jaeger** — сборщик OpenTelemetry-трасс, UI на порту 16686
- **correlator** — базовый экземпляр коррелятора, собирается из `agents/correlator/Dockerfile`
- **scaler** — демон авто-масштабирования, монтирует `/var/run/docker.sock`

---

### `agents/log-collector/main.go`

Первый агент в pipeline. Подписывается на топик `logs.raw`, принимает произвольные строки логов и нормализует их в структурированный JSON (`NormalizedEvent`). Публикует результат в `logs.normalized`.

**Ключевые функции:**
- `normalizeLog(raw)` — извлекает IP (`from X.X.X.X`), порт (`port N`), пользователя (`for user from`) с помощью regexp; классифицирует событие по ключевым словам (`strings.Contains`)
- Типы событий: `auth_failure` (WARNING), `port_scan` (ERROR), `ddos` (CRITICAL), `normal` (INFO), `unknown` (INFO)
- Инкрементирует `stats:log_collector` и `queue:depth` в Redis после каждого publish

---

### `agents/log-collector/main_test.go`

8 unit-тестов для функции `normalizeLog`. Покрывают все классы событий, извлечение IP/порта, сохранение оригинальной строки в поле `raw`, генерацию UUID.

---

### `agents/correlator/main.go`

Агент корреляции. Использует **NATS queue group** (`QueueSubscribe("logs.normalized", "correlators")`) — каждое сообщение обрабатывается ровно одним экземпляром из группы, что обеспечивает корректное разделение нагрузки при масштабировании. Декрементирует `queue:depth` при каждом receive.

**Паттерны обнаружения:**
| Паттерн | Условие | Confidence |
|---|---|---|
| `brute_force` | >5 `auth_failure` с одного IP за 60 с | 0.85 |
| `port_scan` | >10 уникальных портов с одного IP за 60 с | 0.75 |
| `ddos` | >20 уникальных источников на один dest-IP за 60 с | 0.90 |

**Дедупликация:** ключ `incident_sent:{pattern}:{ip}` с TTL 120 с предотвращает публикацию повторных инцидентов.

**Обход ключей:** `SCAN` вместо `KEYS` — не блокирует Redis при большом числе событий.

---

### `agents/correlator/Dockerfile`

Multi-stage сборка: `golang:1.21-alpine` компилирует бинарник, финальный образ — `alpine:latest`. Контекст сборки — корень модуля `siem-lab/`.

```bash
# Сборка образа:
cd siem-lab
docker build -f agents/correlator/Dockerfile -t siem-correlator:latest .
```

---

### `agents/correlator/auction.go`

Функция `handleAuction` — механизм аукционного распределения задач. Оркестратор публикует задачу в `tasks.auction`, агенты отвечают ставкой (`cost`) в `tasks.bids`. Correlator ставит cost=0.3 (загрузка 30%).

---

### `agents/blocker/main.go`

Финальный агент pipeline. Подписывается на `threat.verdict`, принимает решение о блокировке и формирует правила firewall.

**Логика принятия решений (`processVerdict`):**
| Вердикт | Уровень | Действие | Redis | Длительность |
|---|---|---|---|---|
| `TRUE_POSITIVE` | HIGH | blocked + iptables DROP | `SADD blocked_ips` | 1440 мин (24 ч) |
| `TRUE_POSITIVE` | CRITICAL | blocked + iptables DROP | `SADD blocked_ips` | 4320 мин (72 ч) |
| `TRUE_POSITIVE` | MEDIUM | rate_limited | `SADD rate_limited_ips` | 60 мин |
| `SUSPICIOUS` | любой | logged | — | — |
| `FALSE_POSITIVE` | любой | no_action | — | — |

> `rate_limited` не добавляет IP в `blocked_ips` — используется отдельное множество `rate_limited_ips`.

---

### `scaler/main.py`

Python-демон авто-масштабирования. Каждые `POLL_INTERVAL` секунд читает `queue:depth` из Redis и управляет дополнительными экземплярами коррелятора через Docker SDK.

**Алгоритм:**
- `depth > SCALE_UP_THRESHOLD` → `docker.containers.run("siem-correlator:latest", network="siem-network", labels={"siem.managed": "true"})`
- `depth < SCALE_DOWN_THRESHOLD` → `container.stop()` + `container.remove()`
- Максимум `MAX_INSTANCES` динамических контейнеров

Пишет в Redis: `stats:scaler:queue_depth`, `stats:scaler:instances`, `stats:scaler:scale_up_total`, `stats:scaler:scale_down_total`.

---

### `scaler/Dockerfile`

Образ на `python:3.12-alpine` с зависимостями `docker` и `redis`.

---

### `llm-agent/main.py`

Python-агент вынесения вердиктов. Подписывается на `incidents.new`, отправляет инцидент в Anthropic API и публикует вердикт в `threat.verdict`.

**Режимы работы:**
1. **LLM-режим** — запрос к модели через `anthropic.Anthropic`. Системный промпт содержит правила SIEM по MITRE ATT&CK.
2. **Rule-based fallback** (`_rule_based_fallback`) — при недоступности API: `ddos` → CRITICAL, `brute_force` + внешний IP → TRUE_POSITIVE/HIGH, внутренний IP → SUSPICIOUS/MEDIUM.

OpenTelemetry-спан `llm_detect` с атрибутом `llm.used` (true/false). Jaeger-экспортёр использует только `collector_endpoint`.

---

### `orchestrator/main.py`

Python-оркестратор, координирующий pipeline. Не обязателен для работы (агенты общаются напрямую через NATS), но предоставляет API для управления.

**Функции:**
- `send_raw_log(log_string, retries=3)` — публикация лога с retry-логикой (3 попытки, пауза 2 с)
- `listen_incidents(callback)` / `listen_verdicts(callback)` / `listen_blocking_done()` — подписки на топики
- `get_stats()` — чтение всех `stats:*` счётчиков из Redis

---

### `orchestrator/tests/test_orchestrator.py`

5 pytest-тестов с мокированием NATS и Redis:
- `test_send_raw_log_publishes_to_nats` — лог публикуется в правильный топик
- `test_retry_on_timeout` — при ошибке делаются 3 попытки
- `test_retry_exhausted_raises` — после max_retries исключение пробрасывается
- `test_get_stats_reads_redis` — `get_stats` читает все четыре ключа
- `test_get_stats_returns_zero_for_missing_keys` — отсутствующий ключ → 0

---

### `web/dashboard.py`

Streamlit-дашборд с автообновлением каждые 5 секунд.

**Блоки:**
- **Метрики** — четыре счётчика: логов, инцидентов, LLM-вердиктов, блокировок
- **Заблокированные IP** — Redis-множество `blocked_ips`
- **Последние инциденты** — 10 последних записей из `incidents:history`
- **Ручной запуск** — отправка произвольной строки лога в `logs.raw`
- **Симуляция атаки** — отправка N логов брутфорса с заданного IP (слайдер 1–20)

---

### `requirements.txt`

Python-зависимости:
- `nats-py` — async NATS-клиент
- `anthropic>=0.40.0` — Anthropic API SDK
- `redis` — клиент Redis
- `opentelemetry-sdk` + `opentelemetry-exporter-jaeger` — трассировка
- `streamlit` — веб-дашборд
- `docker==7.1.0` — Docker SDK для авто-масштабирования
- `pytest` + `pytest-asyncio` + `pytest-mock` — тестирование
- `python-dotenv` — загрузка `.env`

---

## NATS-топики

| Топик | Кто публикует | Кто подписывается | Формат |
|---|---|---|---|
| `logs.raw` | внешний источник / оркестратор | log-collector | строка лога |
| `logs.normalized` | log-collector | correlator × N (queue group "correlators") | `NormalizedEvent` JSON |
| `incidents.new` | correlator | llm-agent | `Incident` JSON |
| `threat.verdict` | llm-agent | blocker | Verdict JSON |
| `blocking.done` | blocker | оркестратор | `BlockingResult` JSON |
| `tasks.auction` | оркестратор | correlator (handleAuction) | `{"task_id": "..."}` |
| `tasks.bids` | correlator | оркестратор | `{"task_id", "agent_id", "cost"}` |

---

## Redis-ключи

| Ключ | Тип | Описание |
|---|---|---|
| `event:{uuid}` | string (TTL 60 с) | нормализованное событие от log-collector |
| `queue:depth` | counter | глубина очереди: INCR в log-collector, DECR в correlator |
| `stats:log_collector` | counter | количество обработанных логов |
| `stats:correlator` | counter | количество опубликованных инцидентов |
| `stats:llm_agent` | counter | количество выданных вердиктов |
| `stats:blocker` | counter | количество обработанных вердиктов |
| `stats:scaler:queue_depth` | gauge | последнее измеренное значение queue:depth |
| `stats:scaler:instances` | gauge | текущее число динамических корреляторов |
| `stats:scaler:scale_up_total` | counter | сколько раз scaler запустил новый контейнер |
| `stats:scaler:scale_down_total` | counter | сколько раз scaler остановил контейнер |
| `blocked_ips` | set | IP заблокированные при HIGH/CRITICAL угрозе |
| `rate_limited_ips` | set | IP с rate-limit при MEDIUM угрозе |
| `incidents:history` | list (макс. 100) | JSON последних инцидентов |
| `incident_sent:{pattern}:{ip}` | string (TTL 120 с) | дедупликация инцидентов |
