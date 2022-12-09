lint:
	flake8 --ignore=E402,E501,E712,W503,E203,I002,F523 --exclude=venv/ src/ tests/
	black --check --exclude=venv/ src/ tests/

format:
	black --exclude=venv/ src/ tests/

test:
	pytest -rf -c tests/pytest.ini --cov=src --cov-context=test --disable-warnings
	bandit -r src -x venv

delete-data:
	rm -rf .data/*

coverage:
	coverage html --show-contexts

serve:
	flask run

build:
	docker-compose -f docker-compose-local.yml --env-file ./.env.dev build

build-prod:
	docker-compose -f docker-compose.yml --env-file ./.env.prod build

start:
	docker-compose -f docker-compose-local.yml --env-file ./.env.dev up

build-int:
	docker-compose --env-file ./.env.int build idam

start-int:
	docker-compose --env-file ./.env.int up idam

up-force-build:
	docker-compose -f docker-compose-local.yml --env-file ./.env.dev up --build idam

force-build-nocache:
	docker-compose -f docker-compose-local.yml --env-file ./.env.dev build --no-cache idam

clean-all:
	docker system prune -a

stop:
	docker-compose -f docker-compose-local.yml stop

restart:
	docker-compose stop idam
	docker-compose -f docker-compose-local.yml --env-file ./.env.dev up idam

rmi: # remove images (docker)
	docker-compose stop idam
	docker rmi $$(docker images --filter=reference='*idam*' --filter=reference='*/*idam*' -q) --force