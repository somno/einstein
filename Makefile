.PHONY: test
test:
	pipenv run pytest --cov=einstein

.PHONY: run
run:
	pipenv run python einstein/server.py
