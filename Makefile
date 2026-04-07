.PHONY: install-dev lint test build test-package smoke clean

install-dev:
	python -m pip install --upgrade pip
	pip install -e ".[dev]"

lint:
	ruff check rulescope tests

test:
	pytest

build:
	python -m build

test-package: build
	python -m pip install --force-reinstall dist/*.whl
	rulescope version

smoke:
	rulescope scan examples/rules --top-issues 3
	rulescope navigator examples/rules -o /tmp/rulescope_smoke_layer.json
	@echo "Smoke tests passed."

clean:
	rm -rf build dist .pytest_cache .ruff_cache .coverage htmlcov *.egg-info
