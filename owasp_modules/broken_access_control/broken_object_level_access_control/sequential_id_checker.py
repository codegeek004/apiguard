from pathlib import Path
import yaml
import json

file_path = "~/Downloads/schema.yaml" 

def extract_file_data(file_path):
    if not file_path.exists():
        raise FileNotFoundError("Your OpenAPI file not found")

    file_suffix = file_path.suffix.lower()
    
    with open(file_path) as f:
        if file_suffix in ['.yaml', '.yml']:
            return yaml.safe_load(f)
        elif file_suffix == 'json':
            return json.load(f)
        else:
            raise ValueError(f"Filetype {file_suffix} not supported")

paths = extract_file_data(urls_file_path)
if paths is not None:
    print(paths.get("paths", {}))


