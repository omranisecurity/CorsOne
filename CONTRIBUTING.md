# Contributing

Contributions are welcome. Please keep changes focused, test them locally, and include a brief description of the security impact when altering scan logic or payload generation.

## Local setup

```bash
python -m pip install -U pip
python -m pip install -e '.[dev]'
```

## Validation

```bash
pytest
ruff check .
mypy src
```
