.PHONY: run test lint format audit install dev clean docker docker-up docker-down

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

run:
	sundew serve

test:
	pytest tests/ -v --tb=short

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

audit:
	pip-audit
	bandit -r src/ -c pyproject.toml || bandit -r src/
	pytest tests/test_security.py tests/test_anti_detection.py -v --tb=short

docker:
	docker build -t sundew:latest .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
