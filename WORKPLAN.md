# WORKPLAN: Лабораторная работа №13, Вариант 17
# Кибербезопасность (SIEM) — Мультиагентная система

## Контекст для агента

Ты выполняешь лабораторную работу по мультиагентным системам.
Предметная область: SIEM (Security Information and Event Management).
Стек: Go (агенты), Python (оркестратор + LLM-агент), NATS (брокер),
Redis (состояние), Jaeger (трассировка), Streamlit (веб-интерфейс).

Работай строго последовательно по фазам. После каждой фазы проверь
критерий готовности и только потом переходи к следующей.
Все файлы создавай в папке `siem-lab/`.

---

## Фаза 0: Структура проекта

### Задача
Создать файловую структуру и установить все зависимости.

### Команды
```bash
mkdir -p siem-lab/{agents/log-collector,agents/correlator,agents/blocker,orchestrator,llm-agent,web,docker}
cd siem-lab
go mod init siem-lab
```

### Файлы которые нужно создать

**`siem-lab/go.mod`** — добавить зависимости:
```
require (
    github.com/nats-io/nats.go v1.31.0
    github.com/redis/go-redis/v9 v9.0.0
    github.com/google/uuid v1.4.0
    go.opentelemetry.io/otel v1.21.0
    go.opentelemetry.io/otel/exporters/jaeger v1.17.0
    go.opentelemetry.io/otel/sdk v1.21.0
)
```

**`siem-lab/requirements.txt`**:
```
nats-py==2.6.0
anthropic==0.23.0
redis==5.0.1
opentelemetry-sdk==1.21.0
opentelemetry-exporter-jaeger==1.21.0
streamlit==1.29.0
fastapi==0.104.1
uvicorn==0.24.0
pytest==7.4.3
pytest-asyncio==0.21.0
python-dotenv==1.0.0
```

**`siem-lab/.env`**:
```
ANTHROPIC_API_KEY=sk-ant-ВСТАВЬ_СВОЙ_КЛЮЧ_СЮДА
NATS_URL=nats://localhost:4222
REDIS_URL=redis://localhost:6379
JAEGER_URL=http://localhost:14268/api/traces
LLM_MODEL=claude-sonnet-4-20250514
```

### Критерий готовности
- `go mod tidy` завершается без ошибок
- `pip install -r requirements.txt` завершается без ошибок
- Все папки существуют: `ls siem-lab/agents/`

---

## Фаза 1: Инфраструктура (Docker)

### Задача
Поднять NATS, Redis, Jaeger через Docker Compose.

### Файл `siem-lab/docker/docker-compose.yml`
```yaml
version: '3.8'
services:
  nats:
    image: nats:latest
    ports:
      - "4222:4222"
      - "8222:8222"

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"

  jaeger:
    image: jaegertracing/all-in-one:latest
    environment:
      - COLLECTOR_OTLP_ENABLED=true
    ports:
      - "16686:16686"
      - "14268:14268"
      - "4317:4317"
```

### Команды
```bash
cd siem-lab/docker
docker compose up -d
sleep 5
```

### Критерий готовности
```bash
docker ps | grep -E "nats|redis|jaeger"   # все 3 контейнера Up
curl -s http://localhost:8222/healthz      # ответ OK
curl -s http://localhost:16686 | head -5   # HTML страница Jaeger
redis-cli ping                             # PONG
```

---

## Фаза 2: Go-агенты

### Задание 2.1 — Агент 1: Сборщик логов

**Файл:** `siem-lab/agents/log-collector/main.go`

Агент:
- Подписывается на NATS-топик: `logs.raw`
- Нормализует строку лога в JSON
- Публикует результат в: `logs.normalized`
- Сохраняет счётчик в Redis: `INCR stats:log_collector`

Входные данные (строка лога, пример):
```
2024-01-15T10:23:41 sshd[1234]: Failed password for root from 192.168.1.5 port 22 ssh2
```

Выходной JSON (`logs.normalized`):
```json
{
  "id": "uuid-v4",
  "timestamp": "2024-01-15T10:23:41Z",
  "source_ip": "192.168.1.5",
  "dest_ip": "0.0.0.0",
  "port": 22,
  "protocol": "tcp",
  "event_type": "auth_failure",
  "severity": "WARNING",
  "username": "root",
  "raw": "оригинальная строка лога"
}
```

Правила определения `event_type`:
- строка содержит "Failed password" или "authentication failure" → `auth_failure`, severity `WARNING`
- строка содержит "port scan" или "nmap" → `port_scan`, severity `ERROR`
- строка содержит "DDoS" или "flood" → `ddos`, severity `CRITICAL`
- строка содержит "Accepted password" или "session opened" → `normal`, severity `INFO`
- иначе → `unknown`, severity `INFO`

Логирование:
```go
log.Printf("[LOG-COLLECTOR] id=%s event_type=%s source_ip=%s", id, eventType, sourceIP)
```

### Задание 2.2 — Агент 2: Корреляция событий

**Файл:** `siem-lab/agents/correlator/main.go`

Агент:
- Подписывается на NATS-топик: `logs.normalized`
- Сохраняет каждое событие в Redis с TTL 60 секунд: `SET event:{id} {json} EX 60`
- После каждого события проверяет паттерны по всем событиям из Redis
- Если паттерн найден — публикует инцидент в: `incidents.new`
- Сохраняет счётчик: `INCR stats:correlator`

Паттерны для обнаружения:

1. **Брутфорс** (`brute_force`):
   - Более 5 событий `auth_failure` с одного `source_ip` за последние 60 секунд
   - confidence: 0.85

2. **Сканирование портов** (`port_scan`):
   - Более 10 разных значений `port` с одного `source_ip` за последние 60 секунд
   - confidence: 0.75

3. **DDoS** (`ddos`):
   - Более 20 событий любого типа с разных IP на один `dest_ip` за 60 секунд
   - confidence: 0.90

Выходной JSON (`incidents.new`):
```json
{
  "incident_id": "uuid-v4",
  "pattern": "brute_force",
  "confidence": 0.85,
  "source_ips": ["192.168.1.5"],
  "affected_hosts": ["10.0.0.1"],
  "event_count": 7,
  "time_window_seconds": 60,
  "description": "Обнаружен брутфорс: 7 неудачных попыток входа с 192.168.1.5"
}
```

Если паттернов нет — ничего не публиковать.

### Задание 2.3 — Агент 4: Блокировка трафика

**Файл:** `siem-lab/agents/blocker/main.go`

Агент:
- Подписывается на NATS-топик: `threat.verdict`
- По вердикту формирует правила блокировки
- Публикует результат в: `blocking.done`
- Сохраняет в Redis список заблокированных IP: `SADD blocked_ips {ip}`
- Сохраняет счётчик: `INCR stats:blocker`

Логика по полю `verdict`:
- `TRUE_POSITIVE` + threat_level `HIGH` или `CRITICAL`:
  - action_taken: `blocked`
  - сформировать iptables-команду: `iptables -A INPUT -s {ip} -j DROP`
  - duration: HIGH=1440 мин, CRITICAL=4320 мин
- `TRUE_POSITIVE` + threat_level `MEDIUM`:
  - action_taken: `rate_limited`
  - команда: `iptables -A INPUT -s {ip} -m limit --limit 10/min -j ACCEPT`
- `SUSPICIOUS`:
  - action_taken: `logged`
  - только записать в лог, без блокировки
- `FALSE_POSITIVE`:
  - action_taken: `no_action`

Выходной JSON (`blocking.done`):
```json
{
  "incident_id": "тот же что на входе",
  "action_taken": "blocked",
  "firewall_rules": [
    {
      "command": "iptables -A INPUT -s 192.168.1.5 -j DROP",
      "target_ip": "192.168.1.5",
      "duration_minutes": 1440,
      "reason": "Брутфорс: TRUE_POSITIVE, уровень HIGH"
    }
  ],
  "notification": {
    "send_alert": true,
    "severity": "HIGH",
    "message": "IP 192.168.1.5 заблокирован на 24 часа. Причина: брутфорс."
  }
}
```

Логирование:
```go
log.Printf("[BLOCKER] incident=%s action=%s ips=%v", incidentID, action, blockIPs)
```

### Задание 2.4 — Оркестратор (Python)

**Файл:** `siem-lab/orchestrator/main.py`

Оркестратор управляет pipeline:
`logs.raw` → агент 1 → `logs.normalized` → агент 2 → `incidents.new` → агент 3 (LLM) → `threat.verdict` → агент 4 → `blocking.done`

Функции оркестратора:
1. `send_raw_log(log_string)` — опубликовать лог в `logs.raw`
2. `listen_incidents()` — слушать `incidents.new`, передавать LLM-агенту
3. `listen_verdicts()` — слушать `threat.verdict`, передавать агенту блокировки
4. `get_stats()` — читать из Redis счётчики `stats:*` и возвращать словарь
5. Retry при таймауте: не более 3 попыток, задержка 2 секунды

**Файл:** `siem-lab/orchestrator/tests/test_orchestrator.py`

Написать pytest-тесты с моками NATS:
- `test_send_raw_log_publishes_to_nats()`
- `test_retry_on_timeout()`
- `test_get_stats_reads_redis()`

### Команды для запуска агентов
```bash
# Каждый агент в отдельном терминале:
cd siem-lab && go run agents/log-collector/main.go
cd siem-lab && go run agents/correlator/main.go
cd siem-lab && go run agents/blocker/main.go
cd siem-lab && python orchestrator/main.py
```

### Критерий готовности Фазы 2
```bash
# Отправить тестовый лог и увидеть в консоли агентов обработку:
python -c "
import asyncio, nats
async def test():
    nc = await nats.connect('nats://localhost:4222')
    await nc.publish('logs.raw', b'Failed password for root from 1.2.3.4 port 22')
    await nc.close()
asyncio.run(test())
"
# Ожидаемый результат: в логах агента 1 появится строка [LOG-COLLECTOR]
```

---

## Фаза 3: LLM-агент (Python + Anthropic API)

### Задача
Создать агента детекции угроз, который использует LLM для вынесения вердикта.

### Файл `siem-lab/llm-agent/main.py`

Агент:
- Подписывается на NATS-топик: `incidents.new`
- Отправляет инцидент в LLM с системным промптом (см. ниже)
- Публикует вердикт в: `threat.verdict`
- Сохраняет счётчик: `INCR stats:llm_agent`
- Добавляет OpenTelemetry span для каждого вызова LLM

**Системный промпт для LLM** (вставить в код как константу `SYSTEM_PROMPT`):
```
Ты — агент детекции угроз в SIEM-системе кибербезопасности.

Твоя роль: получить скоррелированный инцидент и вынести финальный вердикт —
реальная ли это атака или ложное срабатывание.

Входные данные: JSON-объект с описанием инцидента от агента корреляции.

Твои задачи:
1. Оцени инцидент по критериям:
   - Уровень уверенности (поле confidence)
   - Известные паттерны атак (MITRE ATT&CK)
   - Репутация IP: адреса 10.x.x.x и 192.168.x.x считать внутренними и менее опасными
   - Количество событий (поле event_count): больше 10 — подозрительнее
2. Классифицируй угрозу:
   - TRUE_POSITIVE — реальная атака, нужно действовать
   - FALSE_POSITIVE — скорее всего безобидная активность
   - SUSPICIOUS — требует проверки аналитиком
3. Определи уровень угрозы: LOW, MEDIUM, HIGH или CRITICAL
4. Сопоставь с тактикой MITRE ATT&CK если применимо

Правила принятия решений:
- confidence > 0.8 + event_count > 5 = скорее всего TRUE_POSITIVE
- Внутренние IP (10.x.x.x, 192.168.x.x) снижают уровень угрозы на один шаг
- pattern = "ddos" всегда HIGH или CRITICAL
- pattern = "brute_force" + внутренний IP = SUSPICIOUS

Выводи ТОЛЬКО валидный JSON без пояснений и без markdown:
{
  "incident_id": "тот же что на входе",
  "verdict": "TRUE_POSITIVE|FALSE_POSITIVE|SUSPICIOUS",
  "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
  "mitre_tactic": "Initial Access|Credential Access|Discovery|Impact|null",
  "recommended_action": "block_ip|rate_limit|alert_only|investigate|none",
  "reasoning": "одно предложение объяснения на русском",
  "block_ips": ["список IP для блокировки или пустой массив"],
  "alert_soc": true
}
```

**Код агента** (структура):
```python
import asyncio, json, os, anthropic, nats, redis
from opentelemetry import trace
from dotenv import load_dotenv

load_dotenv()

SYSTEM_PROMPT = """... (промпт выше) ..."""

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
rdb = redis.Redis.from_url(os.getenv("REDIS_URL"))
tracer = trace.get_tracer("llm-agent")

async def detect_threat(incident: dict) -> dict:
    with tracer.start_as_current_span("llm_detect") as span:
        span.set_attribute("incident.pattern", incident.get("pattern"))
        span.set_attribute("incident.confidence", incident.get("confidence", 0))

        response = client.messages.create(
            model=os.getenv("LLM_MODEL", "claude-sonnet-4-20250514"),
            max_tokens=500,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(incident, ensure_ascii=False)}]
        )
        raw = response.content[0].text.strip()
        verdict = json.loads(raw)
        rdb.incr("stats:llm_agent")
        return verdict

async def main():
    nc = await nats.connect(os.getenv("NATS_URL"))

    async def on_incident(msg):
        incident = json.loads(msg.data.decode())
        print(f"[LLM-AGENT] получен инцидент {incident['incident_id']} pattern={incident['pattern']}")
        verdict = await detect_threat(incident)
        print(f"[LLM-AGENT] вердикт: {verdict['verdict']} threat_level={verdict['threat_level']}")
        await nc.publish("threat.verdict", json.dumps(verdict).encode())

    await nc.subscribe("incidents.new", cb=on_incident)
    print("[LLM-AGENT] ожидаю инциденты на topics incidents.new...")
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
```

### Критерий готовности Фазы 3
```bash
cd siem-lab && python llm-agent/main.py
# В другом терминале вручную опубликовать тестовый инцидент:
python -c "
import asyncio, nats, json
async def test():
    nc = await nats.connect('nats://localhost:4222')
    incident = {
        'incident_id': 'test-001',
        'pattern': 'brute_force',
        'confidence': 0.9,
        'source_ips': ['1.2.3.4'],
        'event_count': 8,
        'description': 'Тестовый инцидент'
    }
    await nc.publish('incidents.new', json.dumps(incident).encode())
    await nc.close()
asyncio.run(test())
"
# Ожидаемый результат: LLM-агент выведет вердикт в консоль
```

---

## Фаза 4: Веб-интерфейс (Streamlit)

### Файл `siem-lab/web/dashboard.py`

Веб-панель должна отображать:
1. Метрики (из Redis):
   - Количество обработанных логов (`stats:log_collector`)
   - Количество найденных инцидентов (`stats:correlator`)
   - Количество вердиктов LLM (`stats:llm_agent`)
   - Количество блокировок (`stats:blocker`)
2. Список заблокированных IP из Redis: `SMEMBERS blocked_ips`
3. Список последних инцидентов из Redis: `LRANGE incidents:history 0 9`
4. Кнопка "Отправить тестовый лог" — публикует в `logs.raw` через NATS
5. Автообновление каждые 5 секунд: `st.rerun()` с `time.sleep(5)`

**Структура кода:**
```python
import streamlit as st
import redis, asyncio, nats, json, time
from datetime import datetime

st.set_page_config(page_title="SIEM Dashboard", layout="wide")
st.title("SIEM Monitoring Dashboard — Вариант 17")

rdb = redis.Redis(host="localhost", port=6379, decode_responses=True)

# Метрики
col1, col2, col3, col4 = st.columns(4)
col1.metric("Логов обработано", rdb.get("stats:log_collector") or 0)
col2.metric("Инцидентов найдено", rdb.get("stats:correlator") or 0)
col3.metric("LLM вердиктов", rdb.get("stats:llm_agent") or 0)
col4.metric("Блокировок", rdb.get("stats:blocker") or 0)

# Заблокированные IP
st.subheader("Заблокированные IP")
blocked = rdb.smembers("blocked_ips")
st.write(list(blocked) if blocked else "Нет заблокированных IP")

# Тестовый лог
st.subheader("Ручной запуск")
log_input = st.text_input("Строка лога:", 
    value="Failed password for root from 1.2.3.4 port 22 ssh2")
if st.button("Отправить лог в систему"):
    async def send():
        nc = await nats.connect("nats://localhost:4222")
        await nc.publish("logs.raw", log_input.encode())
        await nc.close()
    asyncio.run(send())
    st.success("Лог отправлен!")

# Автообновление
time.sleep(5)
st.rerun()
```

### Команда запуска
```bash
cd siem-lab && streamlit run web/dashboard.py
```

### Критерий готовности Фазы 4
- Браузер открывает `http://localhost:8501`
- Метрики обновляются после отправки тестового лога
- Заблокированные IP появляются после срабатывания полного pipeline

---

## Фаза 5: Дополнительные задания

### Задание 5.1 — Масштабирование (задание 5 повышенной сложности)

Запустить 2 экземпляра агента-сборщика:
```bash
# Терминал 1
go run agents/log-collector/main.go

# Терминал 2
go run agents/log-collector/main.go
```

NATS автоматически балансирует нагрузку между подписчиками на один топик.
Продемонстрировать: отправить 10 логов и убедиться что они распределились
между двумя экземплярами (разные PID в логах).

### Задание 5.2 — Аукционное распределение (задание 6)

**Файл:** `siem-lab/agents/correlator/auction.go`

Механизм аукциона:
1. Оркестратор публикует задачу в `tasks.auction` с полем `task_id`
2. Каждый агент-корреляции отвечает в `tasks.bids` своей ставкой:
```json
{"task_id": "...", "agent_id": "correlator-1", "cost": 0.3, "reason": "загрузка 30%"}
```
3. Оркестратор ждёт 500мс, выбирает агента с минимальной `cost`
4. Публикует назначение в `tasks.assigned.{agent_id}`

Метрика `cost` = текущая загрузка агента (количество задач в обработке / 10)

### Задание 5.3 — OpenTelemetry трассировка (задание 3)

Добавить в каждый Go-агент:
```go
import "go.opentelemetry.io/otel"

tracer := otel.Tracer("log-collector")
ctx, span := tracer.Start(context.Background(), "process_log")
defer span.End()
span.SetAttributes(attribute.String("event.type", eventType))
span.SetAttributes(attribute.String("source.ip", sourceIP))
```

Jaeger UI: http://localhost:16686 → выбрать сервис → увидеть трассировку

### Задание 5.4 — Тесты (задание 9)

**Go тесты:** `agents/log-collector/main_test.go`
```go
func TestNormalizeLog_AuthFailure(t *testing.T) {
    log := "Failed password for root from 1.2.3.4 port 22"
    result := normalizeLog(log)
    if result.EventType != "auth_failure" {
        t.Errorf("ожидалось auth_failure, получено %s", result.EventType)
    }
}
```

**Python тесты:** `orchestrator/tests/test_orchestrator.py`
```python
@pytest.mark.asyncio
async def test_send_raw_log(mocker):
    mock_nc = mocker.AsyncMock()
    orchestrator.nc = mock_nc
    await orchestrator.send_raw_log("test log")
    mock_nc.publish.assert_called_once_with("logs.raw", b"test log")
```

Запуск:
```bash
cd siem-lab && go test ./agents/...
cd siem-lab && pytest orchestrator/tests/ -v
```

---

## Финальная проверка всей системы

### Интеграционный тест — запустить в конце

```bash
# 1. Убедиться что всё запущено:
docker ps                          # nats, redis, jaeger
# агенты go и python запущены в отдельных терминалах

# 2. Симуляция брутфорса — отправить 8 логов с одного IP:
python -c "
import asyncio, nats

async def simulate_brute_force():
    nc = await nats.connect('nats://localhost:4222')
    for i in range(8):
        log = f'Failed password for root from 5.5.5.5 port 22 attempt {i}'
        await nc.publish('logs.raw', log.encode())
        print(f'Отправлен лог {i+1}/8')
    await nc.close()

asyncio.run(simulate_brute_force())
"

# 3. Подождать 10 секунд и проверить результат:
sleep 10
redis-cli SMEMBERS blocked_ips     # должен содержать 5.5.5.5
redis-cli GET stats:log_collector  # должно быть >= 8
redis-cli GET stats:llm_agent      # должно быть >= 1
```

### Ожидаемый результат полного pipeline:
```
[LOG-COLLECTOR] id=xxx event_type=auth_failure source_ip=5.5.5.5
[CORRELATOR] обнаружен брутфорс: 8 попыток с 5.5.5.5
[LLM-AGENT] получен инцидент xxx pattern=brute_force
[LLM-AGENT] вердикт: TRUE_POSITIVE threat_level=HIGH
[BLOCKER] incident=xxx action=blocked ips=[5.5.5.5]
```

---

## Что сдавать

1. Папка `siem-lab/` со всеми файлами
2. Скриншот Jaeger UI с трассировкой (http://localhost:16686)
3. Скриншот Streamlit dashboard (http://localhost:8501)
4. Вывод консоли с интеграционным тестом (логи всех 4 агентов)
5. Результат `go test ./...` и `pytest -v`

---

## Примечания

- Если нет ключа Anthropic API — можно использовать DeepSeek API
  (поменять базовый URL на `https://api.deepseek.com` и модель на `deepseek-chat`)
- Если локальный Ollama — поменять `client` на `openai`-совместимый с URL `http://localhost:11434/v1`
- Для ручной проверки достаточно показать что в логах видно взаимодействие агентов
- Redis хранит состояние: после перезапуска агент-корреляции восстанавливает события из Redis
