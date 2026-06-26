# detector/contracts — load + validate the language-agnostic JSON-Schema contracts.
# Resolves the contracts dir, validates instances (cross-file $ref), loads the rule registry.

"""Loading + validating the language-agnostic contracts.

The schemas in ``contracts/`` are upstream of code in every language; this module is the Python
gateway to them. It resolves the contracts directory, validates instances (with cross-file ``$ref``
support), and loads the coherence-rule registry.
"""

from __future__ import annotations

import json
import os
from functools import cache, lru_cache
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

__all__ = [
    "ValidationError",
    "contracts_dir",
    "load_rule_registry",
    "load_schema",
    "validate",
]

_SCHEMA_FILES = (
    "signal.schema.json",
    "session.schema.json",
    "verdict.schema.json",
    "coherence-rule.schema.json",
    "challenge.schema.json",
    "finding.schema.json",
)


def _looks_like_contracts(path: Path) -> bool:
    return (path / "signal.schema.json").is_file()


@lru_cache(maxsize=1)
def contracts_dir() -> Path:
    """Locate ``contracts/``.

    Order: ``KITSUNE_CONTRACTS_DIR`` env var, then walk up from this file looking for a sibling
    ``contracts/`` directory (works from the detector package or an installed checkout).
    """
    override = os.environ.get("KITSUNE_CONTRACTS_DIR")
    if override:
        path = Path(override)
        if not _looks_like_contracts(path):
            raise FileNotFoundError(f"KITSUNE_CONTRACTS_DIR={path} is not a contracts directory")
        return path

    for parent in Path(__file__).resolve().parents:
        candidate = parent / "contracts"
        if _looks_like_contracts(candidate):
            return candidate
    raise FileNotFoundError("could not locate the contracts/ directory; set KITSUNE_CONTRACTS_DIR")


@cache
def load_schema(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((contracts_dir() / name).read_text())
    return data


@lru_cache(maxsize=1)
def _registry() -> Registry:
    resources = []
    for name in _SCHEMA_FILES:
        schema = load_schema(name)
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


@cache
def _validator(schema_name: str) -> Draft202012Validator:
    return Draft202012Validator(load_schema(schema_name), registry=_registry())


def validate(instance: Any, schema_name: str) -> None:
    """Validate ``instance`` against a named schema; raises ``ValidationError`` on failure."""
    _validator(schema_name).validate(instance)


def load_rule_registry() -> tuple[str, list[dict[str, Any]]]:
    """Load + schema-validate the coherence-rule registry.

    Returns ``(ruleset_version, rules)``. Every rule is validated against
    ``coherence-rule.schema.json`` so a malformed registry fails fast at load time.
    """
    raw = yaml.safe_load((contracts_dir() / "rules" / "registry.yaml").read_text())
    version = raw["ruleset_version"]
    rules: list[dict[str, Any]] = raw["rules"]
    for rule in rules:
        validate(rule, "coherence-rule.schema.json")
    return version, rules
