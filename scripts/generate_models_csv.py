from __future__ import annotations

import argparse
import csv
import io
from pathlib import Path

EXPECTED_HEADER = ["model_number", "marketing_name", "ebus_model", "notes"]
START_MARKER = "<!-- models.csv:start -->"
END_MARKER = "<!-- models.csv:end -->"


def _extract_models_csv_block(markdown: str) -> str:
    start = markdown.find(START_MARKER)
    if start == -1:
        raise ValueError(f"Missing start marker: {START_MARKER}")
    start += len(START_MARKER)

    end = markdown.find(END_MARKER, start)
    if end == -1:
        raise ValueError(f"Missing end marker: {END_MARKER}")

    block = markdown[start:end].strip()
    if not block:
        raise ValueError("models.csv block is empty")

    lines = block.splitlines()
    if lines and lines[0].lstrip().startswith("```"):
        # Allow fenced code blocks for readability:
        # ```csv
        # ...
        # ```
        fence_end = None
        for i in range(len(lines) - 1, 0, -1):
            if lines[i].strip().startswith("```"):
                fence_end = i
                break
        if fence_end is None or fence_end == 0:
            raise ValueError("Unterminated fenced block in models.csv section")
        lines = lines[1:fence_end]

    csv_text = "\n".join(lines).strip("\n") + "\n"
    return csv_text


def load_models_rows_from_agents_md(agents_md_path: Path) -> list[dict[str, str]]:
    markdown = agents_md_path.read_text(encoding="utf-8")
    csv_text = _extract_models_csv_block(markdown)

    reader = csv.DictReader(io.StringIO(csv_text))
    if reader.fieldnames != EXPECTED_HEADER:
        raise ValueError(
            f"Unexpected CSV header in {agents_md_path}. "
            f"expected={EXPECTED_HEADER} got={reader.fieldnames}"
        )

    rows: list[dict[str, str]] = []
    for row in reader:
        normalized = {k: (row.get(k) or "").strip() for k in EXPECTED_HEADER}
        rows.append(normalized)

    seen_model_numbers: set[str] = set()
    for row in rows:
        model_number = row["model_number"]
        if not model_number.isdigit():
            raise ValueError(f"Invalid model_number (expected digits): {model_number!r}")
        if model_number in seen_model_numbers:
            raise ValueError(f"Duplicate model_number: {model_number}")
        seen_model_numbers.add(model_number)

    rows.sort(key=lambda r: int(r["model_number"]))
    return rows


def write_models_csv(rows: list[dict[str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, lineterminator="\n")
        writer.writerow(EXPECTED_HEADER)
        for row in rows:
            writer.writerow([row[k] for k in EXPECTED_HEADER])


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Regenerate data/models.csv from AGENTS.md.")
    parser.add_argument(
        "--agents",
        type=Path,
        default=repo_root / "AGENTS.md",
        help="Path to AGENTS.md containing the models.csv block markers.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=repo_root / "data" / "models.csv",
        help="Output path for generated models.csv.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    rows = load_models_rows_from_agents_md(args.agents)
    write_models_csv(rows, args.output)
    print(f"Wrote {len(rows)} rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
