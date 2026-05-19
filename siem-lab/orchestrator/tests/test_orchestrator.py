import asyncio
import sys
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import orchestrator.main as orchestrator


@pytest.fixture(autouse=True)
def mock_redis():
    """Мокаем Redis для всех тестов."""
    with patch.object(orchestrator, "rdb", MagicMock()) as mock_rdb:
        mock_rdb.get.return_value = None
        yield mock_rdb


@pytest.mark.asyncio
async def test_send_raw_log_publishes_to_nats():
    """Проверяет, что send_raw_log публикует сообщение в logs.raw."""
    mock_nc = AsyncMock()
    orchestrator.nc = mock_nc

    await orchestrator.send_raw_log("Failed password for root from 1.2.3.4 port 22")

    mock_nc.publish.assert_called_once_with(
        "logs.raw",
        b"Failed password for root from 1.2.3.4 port 22"
    )


@pytest.mark.asyncio
async def test_retry_on_timeout():
    """Проверяет retry-логику при сбое публикации."""
    mock_nc = AsyncMock()
    mock_nc.publish.side_effect = [
        Exception("timeout"),
        Exception("timeout"),
        None,  # третья попытка успешна
    ]
    orchestrator.nc = mock_nc

    with patch("asyncio.sleep", new_callable=AsyncMock):
        await orchestrator.send_raw_log("test log", retries=3)

    assert mock_nc.publish.call_count == 3


@pytest.mark.asyncio
async def test_retry_exhausted_raises():
    """Проверяет, что после max_retries исключение пробрасывается."""
    mock_nc = AsyncMock()
    mock_nc.publish.side_effect = Exception("connection refused")
    orchestrator.nc = mock_nc

    with patch("asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(Exception, match="connection refused"):
            await orchestrator.send_raw_log("test log", retries=3)

    assert mock_nc.publish.call_count == 3


def test_get_stats_reads_redis(mock_redis):
    """Проверяет, что get_stats читает все счётчики из Redis."""
    mock_redis.get.side_effect = lambda key: {
        "stats:log_collector": "10",
        "stats:correlator": "3",
        "stats:llm_agent": "3",
        "stats:blocker": "2",
    }.get(key)

    stats = orchestrator.get_stats()

    assert stats["stats:log_collector"] == 10
    assert stats["stats:correlator"] == 3
    assert stats["stats:llm_agent"] == 3
    assert stats["stats:blocker"] == 2


def test_get_stats_returns_zero_for_missing_keys(mock_redis):
    """Проверяет, что get_stats возвращает 0 для отсутствующих ключей."""
    mock_redis.get.return_value = None

    stats = orchestrator.get_stats()

    for key in stats:
        assert stats[key] == 0
