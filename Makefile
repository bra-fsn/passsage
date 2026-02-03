.PHONY: install dev test lint format build clean publish publish-test docker-build docker-run

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest -v

lint:
	ruff check src/

format:
	ruff format src/

build: clean
	python -m build

docker-build:
	docker build -t passsage:local .

docker-run: docker-build
	docker run --rm -ti -p 8080:8080 \
		-e AWS_ACCESS_KEY_ID=$${AWS_ACCESS_KEY_ID:-test} \
		-e AWS_SECRET_ACCESS_KEY=$${AWS_SECRET_ACCESS_KEY:-test} \
		-e AWS_DEFAULT_REGION=$${AWS_DEFAULT_REGION:-us-west-2} \
		passsage:local $${ARGS:---s3-endpoint http://localhost:4566 --s3-bucket proxy-cache}

clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

publish: build
	twine upload dist/*

publish-test: build
	twine upload --repository testpypi dist/*
