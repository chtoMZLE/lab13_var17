"""
Авто-масштабирование коррелятора.

Алгоритм:
  1. Каждые POLL_INTERVAL секунд читает queue:depth из Redis.
     Этот счётчик увеличивается на 1 при каждом publish в logs.normalized
     (log-collector) и уменьшается на 1 при каждом receive (correlator).
     Положительное значение = сообщения накапливаются быстрее, чем
     коррелятор их обрабатывает.

  2. Если depth > SCALE_UP_THRESHOLD и запущено < MAX_INSTANCES
     динамических корреляторов — запускает новый контейнер через Docker API.

  3. Если depth < SCALE_DOWN_THRESHOLD и запущено > 0 динамических
     корреляторов — останавливает и удаляет один контейнер.

Динамические контейнеры отличаются от базового (docker-compose) меткой
  siem.managed=true

Базовый коррелятор из docker-compose всегда работает; scaler управляет
только дополнительными экземплярами.
"""
import os
import time

import docker
import redis

REDIS_URL           = os.getenv("REDIS_URL",           "redis://localhost:6379")
SCALE_UP_THRESHOLD  = int(os.getenv("SCALE_UP_THRESHOLD",  "10"))
SCALE_DOWN_THRESHOLD = int(os.getenv("SCALE_DOWN_THRESHOLD", "3"))
MAX_INSTANCES       = int(os.getenv("MAX_INSTANCES",       "3"))
POLL_INTERVAL       = int(os.getenv("POLL_INTERVAL",       "5"))
DOCKER_NETWORK      = os.getenv("DOCKER_NETWORK",      "siem-network")
CORRELATOR_IMAGE    = os.getenv("CORRELATOR_IMAGE",    "siem-correlator:latest")
NATS_URL            = os.getenv("NATS_URL",            "nats://nats:4222")
JAEGER_URL          = os.getenv("JAEGER_URL",          "http://jaeger:14268/api/traces")

MANAGED_LABEL = "siem.managed"

rdb = redis.Redis.from_url(REDIS_URL, decode_responses=True)
docker_client = docker.from_env()


def get_queue_depth() -> int:
    val = rdb.get("queue:depth")
    return max(0, int(val) if val else 0)


def get_managed_instances() -> list:
    return docker_client.containers.list(
        filters={"label": f"{MANAGED_LABEL}=true", "status": "running"}
    )


def scale_up(instance_number: int) -> None:
    name = f"siem-correlator-{instance_number}"
    print(f"[SCALER] scale UP  → запускаю {name}", flush=True)
    docker_client.containers.run(
        CORRELATOR_IMAGE,
        detach=True,
        name=name,
        network=DOCKER_NETWORK,
        labels={MANAGED_LABEL: "true"},
        environment={
            "NATS_URL":  NATS_URL,
            "REDIS_URL": REDIS_URL,
            "JAEGER_URL": JAEGER_URL,
        },
    )
    rdb.incr("stats:scaler:scale_up_total")
    print(f"[SCALER] {name} успешно запущен", flush=True)


def scale_down(instances: list) -> None:
    # Удаляем самый последний по имени (лексикографически)
    target = sorted(instances, key=lambda c: c.name)[-1]
    print(f"[SCALER] scale DOWN → останавливаю {target.name}", flush=True)
    target.stop(timeout=5)
    target.remove()
    rdb.incr("stats:scaler:scale_down_total")
    print(f"[SCALER] {target.name} остановлен и удалён", flush=True)


def main() -> None:
    print(
        f"[SCALER] запущен | "
        f"up_threshold={SCALE_UP_THRESHOLD} "
        f"down_threshold={SCALE_DOWN_THRESHOLD} "
        f"max_dynamic={MAX_INSTANCES} "
        f"interval={POLL_INTERVAL}s "
        f"network={DOCKER_NETWORK}",
        flush=True,
    )

    instance_counter = 0

    while True:
        try:
            depth = get_queue_depth()
            instances = get_managed_instances()
            count = len(instances)

            rdb.set("stats:scaler:queue_depth", depth)
            rdb.set("stats:scaler:instances",   count)

            print(
                f"[SCALER] queue_depth={depth} | dynamic_instances={count}",
                flush=True,
            )

            if depth > SCALE_UP_THRESHOLD and count < MAX_INSTANCES:
                instance_counter += 1
                scale_up(instance_counter)
            elif depth < SCALE_DOWN_THRESHOLD and count > 0:
                scale_down(instances)

        except Exception as exc:
            print(f"[SCALER] ошибка: {exc}", flush=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
