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
	@echo "Integrationstests kommen in Meilenstein 5 (SimpleSAMLphp-Compose)."
