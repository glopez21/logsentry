[build-system]
requires = ["setuptools>=61.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "logsentry"
version = "0.2.0"
description = "Security log parsing toolkit for SOC analysts"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.11"
authors = [
    {name = "w01f"}
]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: MIT License",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Topic :: Security",
]
dependencies = [
    "pandas>=3.0.2",
    "rich>=15.0.0",
    "httpx>=0.27.0",
]

[project.optional-dependencies]
server = ["fastapi>=0.100", "uvicorn>=0.23"]
dev = ["pytest>=8.0", "ruff>=0.5"]
all = ["fastapi", "uvicorn", "pytest", "ruff", "mypy", "stix2"]

[project.scripts]
logsentry = "main:main"

[project.urls]
Homepage = "https://github.com/w01f/logsentry"
Repository = "https://github.com/w01f/logsentry"

[tool.setuptools.packages.find]
where = ["."]
include = ["parsers*", "detection*", "output*", "alerts*", "attack_timeline*", "navigator*", "yara_rules*", "integrity*", "baselines*", "integrations*", "threat_intel*", "siem*", "rules*", "analytics*", "dashboard*", "collector*", "alerters*"]