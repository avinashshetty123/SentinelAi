"""Seed clearly-labelled DEMO data by running every demo scenario through the real pipeline.

Usage (from backend/):  python -m scripts.seed
All records created here have source='demo' and are removed by POST /api/v1/demo/reset.
"""

from __future__ import annotations

import asyncio

from app.core.config import get_settings
from app.database.session import dispose_engine, get_sessionmaker, init_engine
from app.services.demo import runner
from app.services.demo.scenarios import SCENARIOS
from app.services.detection.classifier import load_classifier


async def main() -> None:
    settings = get_settings()
    init_engine(settings)
    load_classifier(settings.classifier_path)
    for scenario_id in SCENARIOS:
        async with get_sessionmaker()() as session:
            run = await runner.start_scenario(session, scenario_id)
        task = runner._active_task
        if task is not None:
            await task
        async with get_sessionmaker()() as session:
            latest = await runner.latest_run(session, scenario_id)
            print(f"{scenario_id}: {latest.status.value if latest else 'unknown'} (run {run.id})")
    await dispose_engine()


if __name__ == "__main__":
    asyncio.run(main())
