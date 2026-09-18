.PHONY: up down test unit security api deployment logs status

up:
	docker compose up --build -d --wait --wait-timeout 180

down:
	docker compose down

unit:
	docker build --target test -f app/Dockerfile -t pg-pooler-mtls-unit .
	docker run --rm pg-pooler-mtls-unit

security:
	docker compose --profile test run --build --rm security-tests

api:
	python3 tests/api_integration.py

deployment:
	python3 tests/deployment.py

test: unit security api deployment

logs:
	docker compose logs --tail=100 -f

status:
	docker compose ps
