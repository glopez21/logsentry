PACKAGE_NAME=logsentry
VERSION?=$(shell grep -m1 '^version\s*=\s*' pyproject.toml | sed -E 's/.*=\s*"([^"]+)"/\1/')

.PHONY: wheel sdist docker clean

wheel:
	python -m pip install --quiet build hatchling hatch-vcs
	python -m build -w

sdist:
	python -m pip install --quiet build hatchling hatch-vcs
	python -m build -s

docker:
	docker build -t $(PACKAGE_NAME):$(VERSION) .

clean:
	rm -rf dist build *.egg-info
