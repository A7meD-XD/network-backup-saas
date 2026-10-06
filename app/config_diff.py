import difflib
import re


_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_COMMON_VOLATILE_HEADERS = (
    re.compile(r"^\s*building configuration\.{0,3}\s*$", re.IGNORECASE),
    re.compile(r"^\s*current configuration\s*:\s*\d+\s+bytes\s*$", re.IGNORECASE),
)
_JUNOS_LAST_COMMIT = re.compile(r"^\s*##\s*last commit\s*:.*$", re.IGNORECASE)
_ROUTEROS_GENERATED = re.compile(
    r"^\s*#\s*\d{4}-\d{2}-\d{2}.*\bby\s+routeros\b.*$", re.IGNORECASE
)


def normalize_config(config_text: str, device_type: str | None = None) -> list[str]:
    """Normalize transport and vendor-generated noise while preserving config syntax."""
    platform = (device_type or "").strip().lower()
    cleaned_text = _ANSI_ESCAPE.sub("", config_text).replace("\r\n", "\n").replace("\r", "\n")
    normalized_lines = []
    for line in cleaned_text.splitlines():
        line = line.rstrip()
        if not line.strip() or any(pattern.match(line) for pattern in _COMMON_VOLATILE_HEADERS):
            continue
        if platform.startswith("juniper") and _JUNOS_LAST_COMMIT.match(line):
            continue
        if platform.startswith("mikrotik") and _ROUTEROS_GENERATED.match(line):
            continue
        normalized_lines.append(line)
    return normalized_lines


def compare_configs(
    previous_config: str,
    latest_config: str,
    device_type: str | None = None,
) -> dict[str, object]:
    """Build a unified diff and structured added/removed line lists."""
    diff_lines = list(
        difflib.unified_diff(
            normalize_config(previous_config, device_type),
            normalize_config(latest_config, device_type),
            fromfile="previous",
            tofile="latest",
            lineterm="",
        )
    )
    return {
        "diff": "\n".join(diff_lines),
        "added_lines": [
            line[1:] for line in diff_lines if line.startswith("+") and not line.startswith("+++")
        ],
        "removed_lines": [
            line[1:] for line in diff_lines if line.startswith("-") and not line.startswith("---")
        ],
    }
