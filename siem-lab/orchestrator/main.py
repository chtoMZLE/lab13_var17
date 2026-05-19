import asyncio
import json
import os
import time

import nats
import redis as redis_lib
from dotenv import load_dotenv

load_dotenv()

NATS_URL = os.getenv("NATS_URL", "nats://localhost:4222")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

rdb = redis_lib.Redis.from_url(REDIS_URL, decode_responses=True)
nc = None  # будет инициализировано в main()


async def send_raw_log(log_string: str, retries: int = MAX_RETRIES) -> None:
    """Публикует лог в topics logs.raw с retry-логикой."""
    for attempt in range(1, retries + 1):
        try:
            await nc.publish("logs.raw", log_string.encode())
            print(f"[ORCHESTRATOR] лог отправлен: {log_string[:80]}")
            return
        except Exception as e:
            if attempt == retries:
                print(f"[ORCHESTRATOR] ошибка отправки после {retries} попыток: {e}")
                raise
            print(f"[ORCHESTRATOR] попытка {attempt}/{retries} неудачна: {e}, повтор через {RETRY_DELAY}с")
            await asyncio.sleep(RETRY_DELAY)


async def listen_incidents(llm_agent_cb=None) -> None:
    """Слушает incidents.new и передаёт LLM-агенту (если задан callback)."""
    async def on_incident(msg):
        incident = json.loads(msg.data.decode())
        print(f"[ORCHESTRATOR] получен инцидент: {incident.get('incident_id')} pattern={incident.get('pattern')}")
        if llm_agent_cb:
            await llm_agent_cb(incident)

    await nc.subscribe("incidents.new", cb=on_incident)
    print("[ORCHESTRATOR] слушаю incidents.new...")


async def listen_verdicts(blocker_cb=None) -> None:
    """Слушает threat.verdict и передаёт агенту блокировки (если задан callback)."""
    async def on_verdict(msg):
        verdict = json.loads(msg.data.decode())
        print(f"[ORCHESTRATOR] получен вердикт: {verdict.get('verdict')} level={verdict.get('threat_level')}")
        if blocker_cb:
            await blocker_cb(verdict)

    await nc.subscribe("threat.verdict", cb=on_verdict)
    print("[ORCHESTRATOR] слушаю threat.verdict...")


async def listen_blocking_done() -> None:
    """Слушает blocking.done и логирует результат."""
    async def on_done(msg):
        result = json.loads(msg.data.decode())
        print(f"[ORCHESTRATOR] блокировка выполнена: action={result.get('action_taken')} incident={result.get('incident_id')}")

    await nc.subscribe("blocking.done", cb=on_done)
    print("[ORCHESTRATOR] слушаю blocking.done...")


def get_stats() -> dict:
    """Читает из Redis счётчики stats:* и возвращает словарь."""
    keys = ["stats:log_collector", "stats:correlator", "stats:llm_agent", "stats:blocker"]
    stats = {}
    for key in keys:
        val = rdb.get(key)
        stats[key] = int(val) if val else 0
    return stats


async def main():
    global nc
    nc = await nats.connect(NATS_URL)
    print(f"[ORCHESTRATOR] подключён к NATS {NATS_URL}")

    await listen_incidents()
    await listen_verdicts()
    await listen_blocking_done()

    print("[ORCHESTRATOR] pipeline запущен. Нажмите Ctrl+C для выхода.")
    print("[ORCHESTRATOR] stats:", get_stats())

    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        await nc.close()


if __name__ == "__main__":
    asyncio.run(main())
