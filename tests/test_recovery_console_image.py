"""Contract checks supplement the real restricted-image and HTTPS acceptance."""
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_console_recipe_is_independent_and_pins_base_and_dependencies():
    recipe = (ROOT / "Dockerfile.recovery").read_text()
    assert "python:3.12-alpine@sha256:" in recipe
    assert "COPY requirements-recovery.txt" in recipe
    assert "app/recovery_console.py app/update_transport.py app/update_ui.py" in recipe
    assert "COPY app ./app" not in recipe
    assert "app.main:app" not in recipe
    assert "apt-get" not in recipe and "apk add" not in recipe
    requirements = (ROOT / "requirements-recovery.txt").read_text().splitlines()
    assert requirements and all("==" in value for value in requirements if value.strip())


def test_acceptance_requires_distinct_image_and_second_console_shutdown():
    fixture = (ROOT / "tests/run_recovery_install_acceptance.py").read_text()
    assert 'console_id == image' in fixture
    assert 'engine.inspect(name + "-console")["Image"] == console_id' in fixture
    assert fixture.count('assert not engine.inspect(name + "-console")["State"]["Running"]') == 2
    assert '"distinct_console_image": console_id != image' in fixture
