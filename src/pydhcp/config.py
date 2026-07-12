import json as _json
import typing as _ty


def load_config(filepath: str) -> _ty.Dict[str, _ty.Any]:
    with open(filepath, "r", encoding="utf-8") as f:
        return _json.load(f)
