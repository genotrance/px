VERSION := $(shell grep '^version' pyproject.toml | head -1 | cut -d'"' -f2)
TAG := genotrance/px

.PHONY: install
install: ## Install the virtual environment and pre-commit hooks
	@uv sync --upgrade-package quickjs-ng
	@uv pip install -e . -f mcurllib
	@uv run python -c "import importlib.metadata as m; print(\"quickjs-ng version:\", m.version(\"quickjs-ng\"))"
	@uv run python -m pre_commit install

.PHONY: check
check: ## Run code quality tools
	@uv run pre-commit run -a
	@uv run mypy

.PHONY: test
test: ## Run the test suite with coverage
	@uv run python -m pytest tests -n auto --cov --cov-config=pyproject.toml --cov-report=xml

.PHONY: test-musl
test-musl: ## Build and test in musl (Alpine) containers
	@. ./build.sh && build_local musl

.PHONY: test-glibc
test-glibc: ## Build and test in glibc (manylinux) containers
	@. ./build.sh && build_local glibc

.PHONY: docker
docker: ## Build local Docker images (full and mini)
	docker build -f docker/Dockerfile --network host --build-arg BUILDER=local \
		--target mini -t $(TAG):$(VERSION)-mini -t $(TAG):latest-mini .
	docker build -f docker/Dockerfile --network host --build-arg BUILDER=local \
		-t $(TAG):$(VERSION) -t $(TAG):latest .

.PHONY: docker-kerberos
docker-kerberos: docker ## Build Docker images for Kerberos integration tests
	docker build -f docker/Dockerfile.mit-kdc --network host -t px-test-mit-kdc .
	docker build -f docker/Dockerfile.heimdal-kdc --network host -t px-test-heimdal-kdc .
	docker build -f docker/Dockerfile.heimdal-client --network host -t px-test-heimdal-client .

.PHONY: test-kerberos
test-kerberos: docker-kerberos ## Run Kerberos integration tests against a local KDC in Docker
	@uv run python -m pytest tests/test_kerberos.py -m integration -v

.PHONY: benchmark
benchmark: ## Run concurrency benchmarks
	@uv run python -m pytest tests/test_benchmark.py -m benchmark -v -s

.PHONY: test-large-data
test-large-data: ## Run large data transfer reliability tests
	@uv run python -m pytest tests/test_large_data.py -m largedata -v -s

.PHONY: build
build: clean ## Build sdist and wheel
	@uv build

.PHONY: clean
clean: ## Remove build artifacts
	@rm -rf dist/ build/ *.egg-info px_proxy.egg-info
	@rm -f .coverage coverage.xml

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
