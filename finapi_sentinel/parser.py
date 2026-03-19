import yaml
from pathlib import Path

def parse_openapi(file_path: Path) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            spec = yaml.safe_load(f)
        if not isinstance(spec, dict) or "paths" not in spec:
            raise ValueError("Invalid OpenAPI file: missing 'paths' section")
        return spec
    except (yaml.YAMLError, ValueError) as e:
        raise ValueError(f"Invalid YAML/OpenAPI format: {str(e)}")
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {file_path}")