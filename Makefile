.PHONY: test smoke pilot publication clean

test:
	python -m pip install -e '.[dev]'
	pytest

smoke:
	docker compose run --rm experiment run --suite /app/scenarios/smoke.yaml

pilot:
	docker compose run --rm experiment run --suite /app/scenarios/pilot.yaml

publication:
	docker compose run --rm experiment run --suite /app/scenarios/publication.yaml

clean:
	docker compose down -v --remove-orphans
