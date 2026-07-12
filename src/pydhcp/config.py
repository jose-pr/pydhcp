import json as _json
import configparser as _configparser
import typing as _ty


def load_config(filepath: str) -> _ty.Dict[str, _ty.Any]:
    if filepath.lower().endswith(".ini"):
        parser = _configparser.ConfigParser()
        parser.read(filepath, encoding="utf-8")
        return {section: dict(parser.items(section)) for section in parser.sections()}

    with open(filepath, "r", encoding="utf-8") as f:
        data = _json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Configuration must be a JSON object")
        return _ty.cast(_ty.Dict[str, _ty.Any], data)
