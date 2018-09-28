.PHONY: test
test:
	pipenv run pytest --cov=einstein

.PHONY: run
run:
	pipenv run python einstein/server.py

.PHONY: dump
dump:
	pipenv run python einstein/basic_dump.py
