# prompt_log.md — Лог сессии ИИ-агента
## Лабораторная работа №13, Вариант 17 — SIEM мультиагентная система

**Инструмент:** Claude Code (agentic режим)  
**ОС:** Windows 11 + WSL2 Ubuntu + Docker Desktop  

---

## Общая структура сессии

Агент выполнял WORKPLAN.md последовательно по фазам. Всего выполнено ~120 инструментальных вызовов (PowerShell, Bash, Write, Read, Edit). 

---

## Фаза 0 — Структура проекта

### Промпт агента (из WORKPLAN.md)
```
Создать файловую структуру и установить все зависимости.
Выполнить: mkdir -p siem-lab/{agents/log-collector,...}
Создать go.mod, requirements.txt, .env
Критерий: go mod tidy и pip install завершаются без ошибок.
```

### Действия агента
- Создал структуру папок через PowerShell
- Написал `go.mod`, `requirements.txt`, `.env` с заглушкой API-ключа

### Результат
✅ Структура создана. Ошибок нет.

---

## Фаза 1 — Инфраструктура Docker

### Промпт агента
```
Поднять NATS, Redis, Jaeger через docker-compose.yml.
Запустить: docker compose up -d
Критерий: docker ps показывает все 3 контейнера Up.
```

### ❌ Ошибка 1 — Docker Hub недоступен (главная проблема сессии)

**Симптом:**
```
Error response from daemon: failed to resolve reference "docker.io/library/nats:latest":
failed to do request: Head "https://registry-1.docker.io/v2/...": Not Found
```

**Диагностика агента:**
Агент определил, что Docker Desktop использует встроенный hub proxy на `127.0.0.1:10801`, который не запущен. Команда `netstat` показала, что порт `1080` слушается, но `10801` — нет.

**Решение агента — написал собственный HTTP CONNECT прокси на Go (`miniproxy`):**

```go
// miniproxy/main.go — написан агентом с нуля
func handleConnect(w http.ResponseWriter, r *http.Request) {
    dest, _ := net.Dial("tcp", r.Host)
    // ... туннелирование TCP
}
func main() {
    http.ListenAndServe(":10801", nil)
}
```

### ❌ Ошибка 2 — Неверная платформа бинарника

**Попытка 1:** Агент скомпилировал прокси под `linux/amd64` (для Docker VM) и пытался скопировать через `/mnt/c/`:
```
cp: cannot stat '/mnt/c/Users/zacha/.../miniproxy': No such file or directory
```

**Вывод агента:** *"Go установлен на Windows. Скомпилирую простой HTTP CONNECT прокси для Docker VM."*

**Исправление:** Агент нашёл правильный путь монтирования — `/mnt/host/c/` вместо `/mnt/c/`:
```bash
wsl -d docker-desktop -- sh -c \
  "cp '/mnt/host/c/Users/zacha/.../miniproxy.bin' /tmp/miniproxy"
# Результат: -rwxr-xr-x 1 root root 8.6M /tmp/miniproxy ✅
```

### ❌ Ошибка 3 — Прокси запущен в VM вместо Windows-хоста

**Симптом:** После запуска в Docker VM образы всё равно не скачивались:
```
connectex: No connection could be made because the target machine actively refused it.
```

**Вывод агента:** *"connectex — это Windows-ошибка! Прокси должен работать на Windows-хосте, не в VM. Убиваю его в VM и запускаю на Windows."*

**Попытка запустить Linux-бинарник на Windows:**
```
Start-Process : This command cannot be run due to the error: %1 is not a valid Win32 application.
```

**Исправление:** Перекомпилировал под `windows/amd64`:
```powershell
$env:GOOS="windows"; $env:GOARCH="amd64"; $env:CGO_ENABLED="0"
go build -o miniproxy.exe miniproxy\main.go
# Результат: TCP 0.0.0.0:10801 LISTENING ✅
```

### ❌ Ошибка 4 — Docker всё равно получает `Not Found` вместо данных

**Симптом после запуска прокси на Windows:**
```
Error: "registry-1.docker.io:443": Not Found
```
Ошибка изменилась с `connection refused` на `Not Found` — значит прокси подключается, но что-то не так с туннелированием HTTPS.

**Диагностика:** Агент несколько раз переписывал `miniproxy/main.go` (3 итерации), добавляя:
- Логирование всех соединений в файл
- Сниффинг первых байт TCP-запроса
- Поддержку raw TCP туннелей вместо HTTP CONNECT

**Финальная версия miniproxy** — raw TCP туннель:
```go
// Читаем первые байты, определяем протокол
buf := make([]byte, 4096)
conn.SetReadDeadline(time.Now().Add(5 * time.Second))
n, err := conn.Read(buf)
// Если HTTP CONNECT — парсим заголовок и туннелируем
// Иначе — пробрасываем как есть
```

### ✅ Итог Фазы 1

После 4-й итерации miniproxy образы скачались:
```
NATS скачан! Прокси работает. Скачиваем остальные образы.
Status: Downloaded newer image for nats:latest
Status: Downloaded newer image for redis:alpine  
Status: Downloaded newer image for jaegertracing/all-in-one:latest
Все три образа скачаны.

Container docker-nats-1    Started ✅
Container docker-redis-1   Started ✅
Container docker-jaeger-1  Started ✅
```

**Затрачено итераций:** 7 попыток pull, 3 переписывания miniproxy, ~25 инструментальных вызовов.

---

## Фаза 2 — Go-агенты и тесты

### Промпт агента
```
Реализовать агентов log-collector, correlator, blocker на Go.
Запустить: go test ./agents/...
Критерий: тесты проходят, отправка тестового лога виден в консоли агента.
```

### Действия агента
Агент написал все три Go-агента согласно WORKPLAN.md. Особо отметим:

- В `log-collector` написал `contains()` вручную вместо `strings.Contains` (замечено в код-ревью)
- В `correlator` реализовал аукционный механизм прямо в `main.go`, а `auction.go` оставил как заглушку с комментарием
- В `blocker` грамотно вынес `processVerdict()` в отдельную функцию

### ❌ Ошибка 5 — Проблема с запуском Python в PowerShell

**Симптом:**
```powershell
python3 -c "async def test(): ..."
# Exit code 1 — PowerShell не понимает многострочный Python
```

**Решение:** Агент переключился на WSL Ubuntu для всех Python-команд:
```bash
wsl -d Ubuntu -- bash -c "/tmp/siem-venv/bin/python3 -c \"...\""
```

### ❌ Ошибка 6 — Python не найден в WSL Ubuntu

**Симптом:**
```
(PowerShell completed with no output)  # python3 не в PATH
Exit code 1
```

**Процесс установки (4 попытки):**
1. `pip install` → `pip` не найден
2. `python3 -m ensurepip` → Exit code 1
3. `apt install python3-pip` → нет доступа к apt без sudo
4. Финальное решение — создать venv через `python3 -m venv /tmp/siem-venv`

**Дополнительная проблема:** `python3.12-venv` не установлен. Агент установил его через `apt` в фоне и дождался завершения через `Read` (чтение файла вывода фоновой задачи).

### ✅ Результат Go-тестов
```
=== RUN   TestNormalizeLog_AuthFailure     --- PASS (0.00s)
=== RUN   TestNormalizeLog_PortScan        --- PASS (0.00s)
=== RUN   TestNormalizeLog_DDoS            --- PASS (0.00s)
=== RUN   TestNormalizeLog_Normal          --- PASS (0.00s)
=== RUN   TestNormalizeLog_Unknown         --- PASS (0.00s)
=== RUN   TestNormalizeLog_HasID           --- PASS (0.00s)
=== RUN   TestNormalizeLog_RawPreserved    --- PASS (0.00s)
=== RUN   TestNormalizeLog_AuthenticationFailure --- PASS (0.00s)
PASS  ok  siem-lab/agents/log-collector  0.373s
```

### ✅ Результат Python-тестов
```
platform linux -- Python 3.12.3, pytest-7.4.3
asyncio: mode=Mode.AUTO, collected 5 items

test_send_raw_log_publishes_to_nats         PASSED [ 20%]
test_retry_on_timeout                        PASSED [ 40%]
test_retry_exhausted_raises                  PASSED [ 60%]
test_get_stats_reads_redis                   PASSED [ 80%]
test_get_stats_returns_zero_for_missing_keys PASSED [100%]

5 passed in 0.29s ✅
```

### ✅ Запуск агентов
```
log-collector PID: 26688   → log-collector running ✅
correlator PID: 26596      → correlator OK ✅
blocker PID: 27928         → blocker OK ✅
```

---

## Фаза 3 — LLM-агент (Python + Anthropic API)

### Промпт агента
```
Создать llm-agent/main.py с системным промптом детекции угроз.
Агент подписывается на incidents.new, вызывает LLM, публикует в threat.verdict.
```

### ❌ Ошибка 7 — Конфликт версий anthropic и httpx

**Симптом при первом запуске:**
```
[LLM-AGENT] API недоступен (BadRequestError), используется rule-based fallback
```

Агент сам определил проблему: *"Need to update the anthropic library — the 0.23.0 version conflicts with the installed httpx version."*

**Исправление:**
```bash
pip install --upgrade anthropic
# Successfully installed anthropic-0.103.1
```

### ❌ Ошибка 8 — API-ключ не настроен / невалиден

**Симптом (сохранился после обновления):**
```
[LLM-AGENT] API недоступен (BadRequestError), используется rule-based fallback
[LLM-AGENT] вердикт: TRUE_POSITIVE threat_level=HIGH
```

**Поведение агента:** Вместо падения системы агент продолжил работу через `_rule_based_fallback()` — детерминированная логика на правилах без LLM.

```python
def _rule_based_fallback(incident: dict) -> dict:
    """Детерминированный вердикт когда LLM недоступен."""
    if pattern == "ddos":
        verdict, threat_level = "TRUE_POSITIVE", "CRITICAL"
    elif pattern == "brute_force" and is_internal:
        verdict, threat_level = "SUSPICIOUS", "MEDIUM"
    elif pattern == "brute_force" and confidence > 0.8 and event_count > 5:
        verdict, threat_level = "TRUE_POSITIVE", "HIGH"
    ...
```

**Итог:** pipeline продолжал работать даже без реального LLM.

### ❌ Ошибка 9 — `block_ips` всегда пустой список

**Симптом:** Агент-блокировщик получал вердикты, но ничего не блокировал:
```
[BLOCKER] incident=1ceb9ac0... action=blocked ips=[]
[BLOCKER] incident=78b062a2... action=blocked ips=[]
```

**Диагностика:** Агент прочитал `correlator/main.go` и нашёл проблему:
> *"Found it — the incident uses `source_ips` (list) not `source_ip`. My fallback code uses the wrong field name."*

В `_rule_based_fallback` код читал `source_ip` (строку), а корреляторный агент слал `source_ips` (список):

```python
# Было (неверно):
source_ip = incident.get("source_ip", "")

# Стало (исправлено агентом):
source_ips = incident.get("source_ips", [])
source_ip = source_ips[0] if source_ips else ""
```

**Действие:** Агент самостоятельно отредактировал `llm-agent/main.py`, перезапустил агента, снова запустил симуляцию.

---

## Интеграционный тест

### Промпт (из WORKPLAN.md)
```
Симуляция брутфорса — отправить 8 логов с одного IP 5.5.5.5.
Ожидаемый результат: IP попадает в blocked_ips в Redis.
```

### Скрипт симуляции (написан агентом)
```python
# /tmp/simulate_brute.py
import asyncio, nats

async def simulate():
    nc = await nats.connect("nats://localhost:4222")
    for i in range(8):
        log = f"Failed password for root from 5.5.5.5 port 22 attempt {i}"
        await nc.publish("logs.raw", log.encode())
        print(f"Sent log {i+1}/8")
    await nc.close()
    print("Brute force simulation done!")

asyncio.run(simulate())
```

### ✅ Полный pipeline отработал

**Вывод LLM-агента:**
```
[LLM-AGENT] получен инцидент xxx pattern=brute_force
[LLM-AGENT] API недоступен (BadRequestError), используется rule-based fallback
[LLM-AGENT] вердикт: TRUE_POSITIVE threat_level=HIGH
```

**Финальное состояние Redis:**
```
stats:log_collector  → 81
stats:correlator     → 189 (дублирование, см. замечание)
stats:llm_agent      → 111
stats:blocker        → 252
blocked_ips          → 5.5.5.5 ✅
incidents:history    → 100 записей ✅
```

---

## Веб-интерфейс (Streamlit)

### Действия агента
- Установил Streamlit в Ubuntu WSL venv
- Запустил `streamlit run web/dashboard.py` через WSL

### ❌ Ошибка 10 — Конфликт версий Streamlit

**Симптом:**
```
pip's dependency resolver does not currently take into account all the packages...
Successfully installed streamlit-1.57.0  # вместо 1.29.0
```

Агент не стал откатывать версию — `1.57.0` обратно совместима с кодом дашборда.

### ✅ Результат
Streamlit дашборд запущен на `http://localhost:8501` с метриками, списком заблокированных IP, историей инцидентов и кнопкой симуляции.

---

## Итоговая таблица ошибок

| # | Ошибка | Тип | Решение | Итераций |
|---|--------|-----|---------|----------|
| 1 | Docker Hub недоступен | Окружение | Написал HTTP CONNECT прокси на Go | 7 |
| 2 | Неверный путь `/mnt/c/` в Docker VM | Окружение | Использовал `/mnt/host/c/` | 2 |
| 3 | Прокси запущен в VM вместо Windows | Логика | Перекомпилировал под `windows/amd64` | 2 |
| 4 | Прокси не туннелирует HTTPS корректно | Логика | Переписал как raw TCP туннель | 3 |
| 5 | Многострочный Python в PowerShell | Окружение | Переключился на WSL Ubuntu | 1 |
| 6 | Python/pip не найден в WSL | Окружение | Создал venv `/tmp/siem-venv` | 4 |
| 7 | Конфликт anthropic 0.23.0 и httpx | Зависимости | `pip install --upgrade anthropic` | 1 |
| 8 | API-ключ невалиден / не настроен | Конфигурация | Работает через rule-based fallback | — |
| 9 | `block_ips` пустой (`source_ip` vs `source_ips`) | Баг в коде | Исправил поле в fallback-функции | 1 |
| 10 | Конфликт версий Streamlit | Зависимости | Принял 1.57.0 вместо 1.29.0 | 1 |

---

## Что агент сделал хорошо

- **Устойчивость к ошибкам** — при недоступном API не упал, а использовал fallback-логику.
- **Самодиагностика** — сам читал логи агентов, Redis, netstat и делал выводы о причине проблемы.
- **Самостоятельно нашёл баг** в своём же коде (`source_ip` vs `source_ips`) через чтение исходника коррелятора.
- **Нестандартное решение** — написал HTTP прокси с нуля, когда стандартный инструмент не работал.

## Что агент сделал плохо / можно улучшить

- **Дублирование инцидентов** — correlator публикует один и тот же инцидент при каждом новом событии (189 инцидентов вместо ~1–2). Агент это не заметил и не исправил.
- **Самописный `contains()`** — использовал ручную реализацию вместо стандартной `strings.Contains`.
- **`auction.go` — заглушка** — оставил файл пустым с комментарием.
- **Много лишних итераций с прокси** — мог бы раньше диагностировать, что нужен Windows-бинарник, а не Linux.
- **API-ключ** — не предупредил заранее что ключ нужно вставить в `.env` до запуска LLM-агента; работает только через fallback.

---

## Используемые системные промпты LLM-агента

Агент использовал следующий системный промпт для вызовов к API (из `llm-agent/main.py`):

```
Ты — агент детекции угроз в SIEM-системе кибербезопасности.
Твоя роль: получить скоррелированный инцидент и вынести финальный вердикт.

Правила принятия решений:
- confidence > 0.8 + event_count > 5 = скорее всего TRUE_POSITIVE
- Внутренние IP (10.x.x.x, 192.168.x.x) снижают уровень угрозы на один шаг
- pattern = "ddos" всегда HIGH или CRITICAL
- pattern = "brute_force" + внутренний IP = SUSPICIOUS

Выводи ТОЛЬКО валидный JSON без пояснений и без markdown.
```

В ходе сессии реальные вызовы к API завершались `BadRequestError`, поэтому использовался `_rule_based_fallback` — детерминированная реализация тех же правил на Python.

# После ревью кода студентом, были найдены и исправлены следующие ошибки:

- log-collector/main.go	Удалена ручная contains, заменена на strings.Contains; исправлен игнор ошибки json.Marshal
- correlator/main.go	rdb.Keys → итерирующий SCAN через scanKeys(); дедупликация инцидентов incident_sent:{pattern}:{ip} с TTL 120s для всех трёх паттернов; аукцион делегирован в handleAuction
- correlator/auction.go	Заглушка заменена реальной функцией handleAuction с правильной обработкой ошибок
- blocker/main.go	data, _ и nc.Publish теперь проверяют ошибки с логированием
- llm-agent/main.py	JaegerExporter — только collector_endpoint, убраны agent_host_name и лишний urlparse
