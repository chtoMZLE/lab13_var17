# Лабораторная работа №13 — Вариант 17
## Многоагентная SIEM-система на основе NATS + Redis + LLM

---

## Содержание

- [Обзор](#обзор)
- [Архитектура](#архитектура)
- [Предварительные требования](#предварительные-требования)
- [Быстрый старт](#быстрый-старт)
- [Запуск по шагам](#запуск-по-шагам)
- [Проверка работы](#проверка-работы)
- [Запуск тестов](#запуск-тестов)
- [Структура проекта](#структура-проекта)
- [Описание файлов](#описание-файлов)
- [NATS-топики](#nats-топики)
- [Redis-ключи](#redis-ключи)

---

## Обзор

Система мониторинга безопасности (SIEM) обнаруживает кибератаки в потоке сырых логов и автоматически блокирует угрозы. Реализованы три класса атак: брутфорс SSH, сканирование портов, DDoS.

**Стек:** Go 1.21 (агенты), Python 3.12 (LLM + оркестратор), NATS (шина сообщений), Redis (состояние), Jaeger (трассировка), Streamlit (дашборд).

---

## Архитектура

```
Источник логов
      │
      ▼  logs.raw
┌─────────────┐
│ log-collector│  Go — нормализует сырые строки в JSON-события
└─────────────┘
      │
      ▼  logs.normalized
┌─────────────┐
│  correlator  │  Go — ищет паттерны (брутфорс / порт-скан / DDoS)
└─────────────┘
      │
      ▼  incidents.new
┌─────────────┐
│  llm-agent   │  Python — выносит вердикт (LLM или rule-based fallback)
└─────────────┘
      │
      ▼  threat.verdict
┌─────────────┐
│   blocker    │  Go — добавляет IP в blocked_ips, имитирует iptables
└─────────────┘
      │
      ▼  blocking.done

Redis ◄──── все агенты пишут счётчики stats:*
Jaeger ◄─── OpenTelemetry-спаны от всех агентов
Streamlit ──► читает Redis, показывает дашборд
```

---

## Предварительные требования

| Инструмент | Версия | Где используется |
|---|---|---|
| Docker Desktop | любая свежая | инфраструктура (NATS, Redis, Jaeger) |
| Go | ≥ 1.21 | три Go-агента |
| Python | 3.12 (рекомендуется через WSL Ubuntu) | LLM-агент, оркестратор, дашборд |
| pip / venv | — | Python-зависимости |

> **Windows:** Python 3.14 несовместим с protobuf (opentelemetry). Используйте Python 3.12 через WSL Ubuntu или системный Python 3.12.

---

## Быстрый старт

```bash
# 1. Клонируйте / перейдите в папку проекта
cd siem-lab

# 2. Скопируйте и заполните .env
cp .env.example .env        # или создайте .env вручную (см. ниже)

# 3. Запустите инфраструктуру
docker compose -f docker/docker-compose.yml up -d

# 4. Установите Python-зависимости (в виртуальном окружении)
python3 -m venv /tmp/siem-venv
/tmp/siem-venv/bin/pip install -r requirements.txt

# 5. Запустите Go-агентов (три отдельных терминала)
go run ./agents/log-collector/main.go
go run ./agents/correlator/main.go
go run ./agents/blocker/main.go

# 6. Запустите LLM-агент (Python)
/tmp/siem-venv/bin/python3 llm-agent/main.py

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
docker compose -f docker/docker-compose.yml up -d
```

Сервисы после старта:

| Сервис | Порт | UI |
|---|---|---|
| NATS | 4222 (клиент), 8222 (HTTP мониторинг) | http://localhost:8222 |
| Redis | 6379 | — |
| Jaeger | 16686 (UI), 14268 (collector) | http://localhost:16686 |

### Шаг 3 — Python-окружение

```bash
python3 -m venv /tmp/siem-venv
/tmp/siem-venv/bin/pip install -r siem-lab/requirements.txt
```

> На Windows используйте WSL Ubuntu с Python 3.12. Установить venv: `sudo apt install python3.12-venv`.

### Шаг 4 — Go-агенты

Запускайте каждый в отдельном терминале из директории `siem-lab/`:

```bash
go run ./agents/log-collector/main.go
go run ./agents/correlator/main.go
go run ./agents/blocker/main.go
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
docker exec <redis-container> redis-cli SMEMBERS blocked_ips

# Счётчики
docker exec <redis-container> redis-cli MGET \
  stats:log_collector stats:correlator stats:llm_agent stats:blocker

# Последние инциденты
docker exec <redis-container> redis-cli LRANGE incidents:history -3 -1
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
    │   └── docker-compose.yml         # NATS, Redis, Jaeger
    │
    ├── agents/
    │   ├── log-collector/
    │   │   ├── main.go                # агент нормализации логов
    │   │   └── main_test.go           # unit-тесты normalizeLog()
    │   ├── correlator/
    │   │   ├── main.go                # агент корреляции событий
    │   │   └── auction.go             # механизм аукциона задач
    │   └── blocker/
    │       └── main.go                # агент блокировки угроз
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

Запускает три сервиса инфраструктуры:
- **nats** — брокер сообщений, порты 4222 (клиент) и 8222 (HTTP мониторинг)
- **redis** — хранилище состояния (счётчики, заблокированные IP, история инцидентов)
- **jaeger** — сборщик OpenTelemetry-трасс, UI на порту 16686

---

### `agents/log-collector/main.go`

Первый агент в pipeline. Подписывается на топик `logs.raw`, принимает произвольные строки логов и нормализует их в структурированный JSON (`NormalizedEvent`). Публикует результат в `logs.normalized`.

**Ключевые функции:**
- `normalizeLog(raw)` — извлекает IP (`from X.X.X.X`), порт (`port N`), пользователя (`for user from`) с помощью regexp; классифицирует событие по ключевым словам
- Типы событий: `auth_failure` (WARNING), `port_scan` (ERROR), `ddos` (CRITICAL), `normal` (INFO), `unknown` (INFO)
- Инкрементирует `stats:log_collector` в Redis
- OpenTelemetry-спан `process_log` с атрибутами `event.type` и `source.ip`

---

### `agents/log-collector/main_test.go`

8 unit-тестов для функции `normalizeLog`. Покрывают все классы событий, извлечение IP/порта, сохранение оригинальной строки в поле `raw`, генерацию UUID.

---

### `agents/correlator/main.go`

Агент корреляции. Подписывается на `logs.normalized`, сохраняет каждое событие в Redis с TTL 60 секунд (`event:{id}`), после каждого события запускает анализ паттернов.

**Паттерны обнаружения:**
| Паттерн | Условие | Confidence |
|---|---|---|
| `brute_force` | >5 `auth_failure` с одного IP за 60 с | 0.85 |
| `port_scan` | >10 уникальных портов с одного IP за 60 с | 0.75 |
| `ddos` | >20 уникальных источников на один dest-IP за 60 с | 0.90 |

**Дедупликация:** перед публикацией инцидента проверяет Redis-ключ `incident_sent:{pattern}:{ip}` с TTL 120 с — исключает спам одинаковыми инцидентами.

**Обход ключей:** использует `SCAN` (неблокирующий итератор) вместо `KEYS`.

Инциденты публикуются в `incidents.new`, дублируются в `incidents:history` (список, последние 100).

---

### `agents/correlator/auction.go`

Реализует функцию `handleAuction` — механизм распределения задач по принципу аукциона. Оркестратор публикует задачу в `tasks.auction`, агенты отвечают ставкой (`cost`) в `tasks.bids`. Агент с минимальной стоимостью получает назначение через `tasks.assigned.{agent_id}`. Correlator всегда ставит cost=0.3 (загрузка 30%).

---

### `agents/blocker/main.go`

Финальный агент pipeline. Подписывается на `threat.verdict`, принимает решение о блокировке и формирует правила firewall.

**Логика принятия решений (`processVerdict`):**
| Вердикт | Уровень | Действие | Длительность |
|---|---|---|---|
| `TRUE_POSITIVE` | HIGH | blocked + iptables DROP | 1440 мин (24 ч) |
| `TRUE_POSITIVE` | CRITICAL | blocked + iptables DROP | 4320 мин (72 ч) |
| `TRUE_POSITIVE` | MEDIUM | rate_limited | 60 мин |
| `SUSPICIOUS` | любой | logged | — |
| `FALSE_POSITIVE` | любой | no_action | — |

Добавляет IP в Redis-множество `blocked_ips`, инкрементирует `stats:blocker`, публикует результат в `blocking.done`.

---

### `llm-agent/main.py`

Python-агент, принимающий решение о природе инцидента. Подписывается на `incidents.new`, отправляет инцидент в Anthropic API и публикует вердикт в `threat.verdict`.

**Режимы работы:**
1. **LLM-режим** — запрос к `claude-sonnet-4-20250514` через `anthropic.Anthropic`. Системный промпт содержит правила SIEM по MITRE ATT&CK.
2. **Rule-based fallback** — при недоступности API (`_rule_based_fallback`) применяет детерминированные правила: `ddos` → CRITICAL, `brute_force` с внешним IP → TRUE_POSITIVE/HIGH, внутренний IP → SUSPICIOUS/MEDIUM и т.д.

Вердикт содержит: `verdict`, `threat_level`, `mitre_tactic`, `recommended_action`, `block_ips`, `reasoning`.

OpenTelemetry-спан `llm_detect` с атрибутом `llm.used` (true/false).

---

### `orchestrator/main.py`

Python-оркестратор, координирующий весь pipeline. Не является обязательным для работы системы (агенты общаются напрямую через NATS), но предоставляет API для управления.

**Функции:**
- `send_raw_log(log_string, retries=3)` — публикация лога с retry-логикой (3 попытки, пауза 2 с)
- `listen_incidents(callback)` — подписка на инциденты
- `listen_verdicts(callback)` — подписка на вердикты
- `listen_blocking_done()` — подписка на результаты блокировки
- `get_stats()` — чтение всех `stats:*` счётчиков из Redis

---

### `orchestrator/tests/test_orchestrator.py`

5 pytest-тестов оркестратора с мокированием NATS и Redis:
- `test_send_raw_log_publishes_to_nats` — лог публикуется в правильный топик
- `test_retry_on_timeout` — при ошибке делаются 3 попытки
- `test_retry_exhausted_raises` — после max_retries исключение пробрасывается
- `test_get_stats_reads_redis` — `get_stats` читает все четыре ключа
- `test_get_stats_returns_zero_for_missing_keys` — отсутствующий ключ → 0

---

### `web/dashboard.py`

Streamlit-дашборд с автообновлением каждые 5 секунд.

**Блоки:**
- **Метрики** — четыре счётчика из Redis: логов, инцидентов, LLM-вердиктов, блокировок
- **Заблокированные IP** — содержимое Redis-множества `blocked_ips`
- **Последние инциденты** — 10 последних записей из `incidents:history`
- **Ручной запуск** — отправка произвольной строки лога в `logs.raw`
- **Симуляция атаки** — отправка N логов брутфорса с заданного IP (слайдер 1–20)

---

### `go.mod`

Go-модуль `siem-lab` с зависимостями:
- `nats.go v1.31.0` — клиент NATS
- `go-redis/v9 v9.0.0` — клиент Redis
- `uuid v1.4.0` — генерация ID событий и инцидентов
- `otel v1.21.0` + `exporters/jaeger v1.17.0` — OpenTelemetry трассировка

---

### `requirements.txt`

Python-зависимости:
- `nats-py` — async NATS-клиент
- `anthropic` — Anthropic API SDK (LLM-агент)
- `redis` — клиент Redis
- `opentelemetry-sdk` + `opentelemetry-exporter-jaeger` — трассировка
- `streamlit` — веб-дашборд
- `pytest` + `pytest-asyncio` — тестирование
- `python-dotenv` — загрузка `.env`

---

### `pytest.ini`

```ini
[pytest]
asyncio_mode = auto
testpaths = orchestrator/tests
```

---

## NATS-топики

| Топик | Кто публикует | Кто подписывается | Формат |
|---|---|---|---|
| `logs.raw` | внешний источник / оркестратор | log-collector | строка лога |
| `logs.normalized` | log-collector | correlator | `NormalizedEvent` JSON |
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
| `stats:log_collector` | counter | количество обработанных логов |
| `stats:correlator` | counter | количество опубликованных инцидентов |
| `stats:llm_agent` | counter | количество выданных вердиктов |
| `stats:blocker` | counter | количество обработанных вердиктов |
| `blocked_ips` | set | IP-адреса, добавленные блокером |
| `incidents:history` | list (макс. 100) | JSON последних инцидентов |
| `incident_sent:{pattern}:{ip}` | string (TTL 120 с) | дедупликация инцидентов |
