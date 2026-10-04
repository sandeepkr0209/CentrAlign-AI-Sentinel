"""Minimal JSON-Schema-style validator (type, required, enum, length, pattern, bounds, items)."""
from __future__ import annotations

import re

_TYPES = {"string": str, "integer": int, "boolean": bool, "array": list, "object": dict, "number": (int, float)}


def validate(value, schema: dict, path: str = "arguments") -> list[str]:
    errors: list[str] = []
    t = schema.get("type")
    if t:
        ok = isinstance(value, _TYPES[t])
        if t in ("integer", "number") and isinstance(value, bool):
            ok = False
        if not ok:
            return [f"{path}: expected {t}, got {type(value).__name__}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']}")
    if t == "string":
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than {schema['minLength']} characters")
        if len(value) > schema.get("maxLength", 10**9):
            errors.append(f"{path}: longer than {schema['maxLength']} characters")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            errors.append(f"{path}: does not match pattern {schema['pattern']}")
    if t in ("integer", "number"):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above maximum {schema['maximum']}")
    if t == "object":
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if req not in value:
                errors.append(f"{path}.{req}: required field is missing")
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append(f"{path}.{key}: unexpected field")
        for key, sub in props.items():
            if key in value:
                errors.extend(validate(value[key], sub, f"{path}.{key}"))
    if t == "array":
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: needs at least {schema['minItems']} item(s)")
        if len(value) > schema.get("maxItems", 10**9):
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if "items" in schema:
            for i, item in enumerate(value):
                errors.extend(validate(item, schema["items"], f"{path}[{i}]"))
    return errors
