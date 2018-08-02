.PHONY: test
test:
	pipenv run pytest

.PHONY: run
run:
	pipenv run python server.py

.PHONY: dummy-subscription
dummy-subscription:
	curl --data '{"callback_url":"http://localhost:8081/"}'  http://localhost:8080/monitor/ff:ff:ff:ff:ff:ff/subscribe
