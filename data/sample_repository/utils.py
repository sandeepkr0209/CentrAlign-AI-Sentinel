"""Configuration helpers."""
import yaml


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.load(handle, Loader=yaml.FullLoader)


def dump_config(config, path):
    with open(path, "w", encoding="utf-8") as handle:
        yaml.safe_dump(config, handle)
