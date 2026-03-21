import json
import yaml
from pathlib import Path


def parse_openapi(file_path: Path) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            if file_path.suffix == ".json":
                spec = json.load(f)
            elif file_path.suffix in (".yaml", ".yml"):
                spec = yaml.safe_load(f)
            else:
                raise ValueError(f"Unsupported file format: '{file_path.suffix}'. Use .json, .yaml, or .yml")

        if not isinstance(spec, dict) or "paths" not in spec:
            raise ValueError("Invalid OpenAPI file: missing 'paths' section")

        return spec

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {str(e)}")
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format: {str(e)}")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")