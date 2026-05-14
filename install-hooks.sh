#!/bin/sh
# Install pre-commit hooks

if ! command -v pre-commit >/dev/null 2>&1; then
    echo "Installing pre-commit..."
    pip install pre-commit
fi

echo "Installing LogSentry pre-commit hooks..."
pre-commit install

echo "Done! Hooks will run on git commit."