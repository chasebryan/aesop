# AESOP — developer convenience targets
PYTHON ?= python3
.PHONY: help install install-core dev test smoke demo gui lint clean

help:
	@echo "AESOP make targets:"
	@echo "  make install       # editable install with all optional accelerators"
	@echo "  make install-core  # editable install, core only (rich)"
	@echo "  make dev           # install + dev tools (pytest)"
	@echo "  make test          # run the full test suite"
	@echo "  make smoke         # quick end-to-end sanity check"
	@echo "  make demo          # run the showcase script"
	@echo "  make gui           # open the graphical workbench"
	@echo "  make clean         # remove build/test artefacts"

install:
	pip install -e ".[full]"

install-core:
	pip install -e .

dev:
	pip install -e ".[full,dev]"

test:
	pytest

smoke:
	@$(PYTHON) -m aesop version >/dev/null && echo "version: ok"
	@$(PYTHON) -m aesop list >/dev/null && echo "list: ok"
	@$(PYTHON) -m aesop caesar 'Wkh txlfn eurzq ira' | grep -qi 'quick brown fox' && echo "caesar: ok"
	@echo 'ZmxhZ3tuZXN0ZWR9' | $(PYTHON) -m aesop magic | grep -q 'flag{nested}' && echo "magic: ok"

demo:
	@bash examples/demo.sh

gui:
	@$(PYTHON) -m aesop gui

lint:
	@$(PYTHON) -m py_compile $$(find aesop -name '*.py') && echo "compile: ok"

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
	find . -name '*.pyc' -delete
