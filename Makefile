.PHONY: test
test:
	pipenv run pytest

.PHONY: run
run:
	pipenv run python einstein/server.py
