# Data Directory

This directory is for non-code assets (JSON, CSV, fixtures, captured payloads, etc).

Guidelines:
- Do not embed large tables or mappings into Python source. Keep them here as data files.
- Prefer human-editable formats and clear filenames.
- Do not commit secrets (tokens, credentials, hostnames, private identifiers).

Files:
- `myvaillant_register_map.csv`: Optional Vaillant-cloud (myVaillant-style) leaf-name annotations for B524 registers.
