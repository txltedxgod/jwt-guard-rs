.PHONY: all test run lint clean docker-build

all: test

test:
	cargo test

run:
	cargo run

lint:
	cargo clippy --all-targets -- -D warnings

clean:
	@echo "Cleaning artifacts..."

docker-build:
	docker build -t app:latest .
