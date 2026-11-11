PYTHON ?= python

.PHONY: help install build run test benchmark

help:
	@echo "Targets: install, build, run, test, benchmark"

install:
	$(PYTHON) -m pip install -r requirements.txt

build:
	$(PYTHON) -m py_compile main.py rsa.py primes.py oaep.py byte_conversion.py benchmark_rsa.py

run:
	$(PYTHON) main.py

test:
	$(PYTHON) -m pytest -v tests/

benchmark:
	$(PYTHON) benchmark_rsa.py
