import asyncio
import json
import time
from datetime import datetime

import nats
import redis
import streamlit as st

st.set_page_config(page_title="SIEM Dashboard", layout="wide")
st.title("SIEM Monitoring Dashboard — Вариант 17")

rdb = redis.Redis(host="localhost", port=6379, decode_responses=True)

# --- Метрики ---
st.subheader("Метрики системы")
col1, col2, col3, col4 = st.columns(4)
col1.metric("Логов обработано", rdb.get("stats:log_collector") or 0)
col2.metric("Инцидентов найдено", rdb.get("stats:correlator") or 0)
col3.metric("LLM вердиктов", rdb.get("stats:llm_agent") or 0)
col4.metric("Блокировок", rdb.get("stats:blocker") or 0)

# --- Заблокированные IP ---
st.subheader("Заблокированные IP")
blocked = rdb.smembers("blocked_ips")
if blocked:
    for ip in sorted(blocked):
        st.code(ip)
else:
    st.info("Нет заблокированных IP")

# --- Последние инциденты ---
st.subheader("Последние инциденты (до 10)")
history = rdb.lrange("incidents:history", -10, -1)
if history:
    for raw in reversed(history):
        try:
            inc = json.loads(raw)
            st.json({
                "pattern": inc.get("pattern"),
                "confidence": inc.get("confidence"),
                "source_ips": inc.get("source_ips"),
                "description": inc.get("description"),
                "event_count": inc.get("event_count"),
            })
        except Exception:
            st.text(raw)
else:
    st.info("Нет инцидентов")

# --- Ручной запуск ---
st.subheader("Ручной запуск")
log_input = st.text_input(
    "Строка лога:",
    value="Failed password for root from 1.2.3.4 port 22 ssh2"
)
if st.button("Отправить лог в систему"):
    async def send():
        nc = await nats.connect("nats://localhost:4222")
        await nc.publish("logs.raw", log_input.encode())
        await nc.close()

    try:
        asyncio.run(send())
        st.success(f"Лог отправлен в logs.raw: {log_input}")
    except Exception as e:
        st.error(f"Ошибка отправки: {e}")

# --- Симуляция брутфорса ---
st.subheader("Симуляция атаки")
sim_ip = st.text_input("IP-адрес атакующего:", value="5.5.5.5")
sim_count = st.slider("Количество попыток:", 1, 20, 8)
if st.button("Симулировать брутфорс"):
    async def simulate():
        nc = await nats.connect("nats://localhost:4222")
        for i in range(sim_count):
            log = f"Failed password for root from {sim_ip} port 22 attempt {i}"
            await nc.publish("logs.raw", log.encode())
        await nc.close()

    try:
        asyncio.run(simulate())
        st.success(f"Отправлено {sim_count} логов с IP {sim_ip}")
    except Exception as e:
        st.error(f"Ошибка симуляции: {e}")

# --- Статус системы ---
st.subheader("Статус")
st.caption(f"Обновлено: {datetime.now().strftime('%H:%M:%S')}")

# Автообновление каждые 5 секунд
time.sleep(5)
st.rerun()
