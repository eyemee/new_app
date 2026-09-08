import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from shootsync.engines.local import LocalReconciler          # noqa: E402
from shootsync.impact import build_change_orders, load_assets  # noqa: E402
from shootsync.parsing import parse_plan, parse_transcript     # noqa: E402

FIXTURE = ROOT / "fixtures" / "NEG-L03"


@pytest.fixture(scope="session")
def lesson():
    return parse_plan((FIXTURE / "master-plan.md").read_text())


@pytest.fixture(scope="session")
def segments():
    return parse_transcript((FIXTURE / "transcript.txt").read_text())


@pytest.fixture(scope="session")
def assets():
    return load_assets(FIXTURE / "assets.json")


@pytest.fixture(scope="session")
def atr(lesson, segments):
    return LocalReconciler().reconcile(lesson, segments, transcript_id="take-02")


@pytest.fixture(scope="session")
def orders(lesson, atr, assets, segments):
    return build_change_orders(lesson, atr, assets, segments)


@pytest.fixture(scope="session")
def by_asset(orders):
    return {o.asset_id: o for o in orders}
