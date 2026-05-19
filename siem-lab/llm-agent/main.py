import asyncio
import json
import os

import anthropic
import nats
import redis
from dotenv import load_dotenv
from opentelemetry import trace
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

load_dotenv()

SYSTEM_PROMPT = """Ты — агент детекции угроз в SIEM-системе кибербезопасности.

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
}"""


def _init_tracer():
    jaeger_url = os.getenv("JAEGER_URL", "http://localhost:14268/api/traces")
    exporter = JaegerExporter(
        collector_endpoint=jaeger_url,
    )
    provider = TracerProvider(
        resource=Resource.create({"service.name": "llm-agent"})
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)


_init_tracer()

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
rdb = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
tracer = trace.get_tracer("llm-agent")


def _rule_based_fallback(incident: dict) -> dict:
    """Детерминированный вердикт когда LLM недоступен."""
    pattern = incident.get("pattern", "")
    confidence = float(incident.get("confidence", 0))
    event_count = int(incident.get("event_count", 0))
    source_ips = incident.get("source_ips", [])
    source_ip = source_ips[0] if source_ips else ""

    is_internal = source_ip.startswith("10.") or source_ip.startswith("192.168.")

    if pattern == "ddos":
        verdict, threat_level = "TRUE_POSITIVE", "CRITICAL"
        action, tactic = "block_ip", "Impact"
    elif pattern == "brute_force" and is_internal:
        verdict, threat_level = "SUSPICIOUS", "MEDIUM"
        action, tactic = "investigate", "Credential Access"
    elif pattern == "brute_force" and confidence > 0.8 and event_count > 5:
        verdict, threat_level = "TRUE_POSITIVE", "HIGH"
        action, tactic = "block_ip", "Credential Access"
    elif pattern == "port_scan":
        verdict, threat_level = "TRUE_POSITIVE", "MEDIUM"
        action, tactic = "rate_limit", "Discovery"
    else:
        verdict, threat_level = "SUSPICIOUS", "LOW"
        action, tactic = "alert_only", "null"

    block_ips = list(source_ips) if verdict == "TRUE_POSITIVE" and action == "block_ip" and source_ips else []

    return {
        "incident_id": incident.get("incident_id", ""),
        "verdict": verdict,
        "threat_level": threat_level,
        "mitre_tactic": tactic,
        "recommended_action": action,
        "reasoning": f"[rule-based fallback] pattern={pattern} confidence={confidence}",
        "block_ips": block_ips,
        "alert_soc": True,
    }


async def detect_threat(incident: dict) -> dict:
    with tracer.start_as_current_span("llm_detect") as span:
        span.set_attribute("incident.pattern", incident.get("pattern", ""))
        span.set_attribute("incident.confidence", float(incident.get("confidence", 0)))

        try:
            response = client.messages.create(
                model=os.getenv("LLM_MODEL", "claude-sonnet-4-20250514"),
                max_tokens=500,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": json.dumps(incident, ensure_ascii=False)}]
            )
            raw = response.content[0].text.strip()
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            verdict = json.loads(raw)
            span.set_attribute("llm.used", True)
        except Exception as api_err:
            print(f"[LLM-AGENT] API недоступен ({api_err.__class__.__name__}), используется rule-based fallback")
            verdict = _rule_based_fallback(incident)
            span.set_attribute("llm.used", False)

        rdb.incr("stats:llm_agent")
        return verdict


async def main():
    nc = await nats.connect(os.getenv("NATS_URL", "nats://localhost:4222"))

    async def on_incident(msg):
        incident = json.loads(msg.data.decode())
        print(f"[LLM-AGENT] получен инцидент {incident['incident_id']} pattern={incident['pattern']}")
        try:
            verdict = await detect_threat(incident)
            print(f"[LLM-AGENT] вердикт: {verdict['verdict']} threat_level={verdict['threat_level']}")
            await nc.publish("threat.verdict", json.dumps(verdict, ensure_ascii=False).encode())
        except Exception as e:
            print(f"[LLM-AGENT] ошибка обработки инцидента: {e}")

    await nc.subscribe("incidents.new", cb=on_incident)
    print("[LLM-AGENT] ожидаю инциденты на topics incidents.new...")
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
