.PHONY: install lint reformat test-local test-integration

install:
	uv pip install -U -e ".[dev]"

lint:
	uv run ruff check .
	uv run ruff format --check .
	uv run ty check src tests

reformat:
	uv run ruff format .
	uv run ruff check --fix .

test-local:
	uv run pytest

test-integration:
	docker compose up -d --wait
	IT_REDIS_URL=redis://localhost:6399/0 \
	IT_DB_URL=postgresql+asyncpg://postgres:pw@localhost:5439/fa \
	uv run pytest -m integration -v; status=$$?; docker compose down -v; exit $$status
