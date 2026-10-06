import re


_DEFAULT_COMMUNITY = re.compile(r"\b(public|private)\b", re.IGNORECASE)
_CISCO_SNMP = re.compile(
    r"^\s*snmp-server\s+community\s+(public|private)(?:\s|$)", re.IGNORECASE
)
_JUNIPER_SET_SNMP = re.compile(
    r"^\s*set\s+snmp\s+community\s+[\"']?(public|private)[\"']?(?:\s|$)",
    re.IGNORECASE,
)
_ROUTEROS_COMMUNITY = re.compile(r"\b(?:name|community)\s*=\s*[\"']?(public|private)\b", re.IGNORECASE)
_FORTINET_COMMUNITY = re.compile(r"^\s*set\s+name\s+[\"']?(public|private)[\"']?\s*$", re.IGNORECASE)
_FORTINET_SNMP_BLOCK = re.compile(
    r"^\s*config\s+system\s+snmp\s+community\s*$([\s\S]*?)^\s*end\s*$",
    re.IGNORECASE | re.MULTILINE,
)


def _platform_name(device_type: str | None, config_text: str) -> str:
    if device_type:
        return device_type.strip().lower()
    lowered = config_text.lower()
    if "line vty" in lowered or "service password-encryption" in lowered:
        return "cisco_ios"
    if "/ip service" in lowered or "/snmp community" in lowered:
        return "mikrotik_routeros"
    if "config system global" in lowered or "config system snmp" in lowered:
        return "fortinet"
    if "system {" in lowered or "set system services" in lowered:
        return "juniper_junos"
    return "unknown"


def _cisco_vty_telnet(config_lines: list[str]) -> bool:
    in_vty_section = False
    for line in config_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("!"):
            in_vty_section = False if stripped.startswith("!") else in_vty_section
            continue
        if re.match(r"^line\s+vty\b", stripped, re.IGNORECASE):
            in_vty_section = True
            continue
        if in_vty_section and re.match(
            r"^(?:line\s+|interface\s+|router\s+|end\b)", stripped, re.IGNORECASE
        ):
            in_vty_section = False
        if in_vty_section and re.match(
            r"^transport\s+input\b.*\btelnet\b", stripped, re.IGNORECASE
        ):
            return True
    return False


def _junos_findings(config_text: str) -> list[str]:
    findings = []
    lines = config_text.splitlines()

    if re.search(r"^\s*set\s+system\s+services\s+telnet\b", config_text, re.IGNORECASE | re.MULTILINE):
        findings.append("Telnet service is enabled in the Junos configuration.")

    block_stack: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        block_match = re.match(r"^(.+?)\s*\{\s*$", stripped)
        if block_match:
            block_stack.append(block_match.group(1).strip('"'))
            continue
        if stripped in {"}", "};"}:
            if block_stack:
                block_stack.pop()
            continue
        if len(block_stack) >= 2 and block_stack[-2:] == ["system", "services"]:
            if re.match(r"^telnet\s*;?$", stripped, re.IGNORECASE):
                findings.append("Telnet service is enabled in the Junos configuration.")
                break

    if re.search(
        r"^\s*set\s+snmp\s+community\s+[\"']?(?:public|private)[\"']?(?:\s|$)",
        config_text,
        re.IGNORECASE | re.MULTILINE,
    ):
        findings.append("Default SNMP community string is configured.")
    else:
        block_stack = []
        for line in lines:
            stripped = line.strip()
            block_match = re.match(r"^(.+?)\s*\{\s*$", stripped)
            if block_match:
                name = block_match.group(1).strip('"')
                if block_stack and block_stack[-1] == "snmp" and _DEFAULT_COMMUNITY.search(name):
                    findings.append("Default SNMP community string is configured.")
                    break
                block_stack.append(name)
            elif stripped in {"}", "};"} and block_stack:
                block_stack.pop()
    return findings


def _routeros_findings(config_text: str) -> list[str]:
    findings = []
    section = ""
    telnet_enabled = False
    default_snmp_community = False

    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("/"):
            section = stripped.lower()
            continue
        lowered = stripped.lower()
        if section.startswith("/ip service") and re.search(r"\b(?:name=telnet|set\s+telnet)\b", lowered):
            if not re.search(r"\bdisabled\s*=\s*yes\b", lowered):
                telnet_enabled = True
        if section.startswith("/snmp community") and _ROUTEROS_COMMUNITY.search(stripped):
            default_snmp_community = True

    if telnet_enabled:
        findings.append("Telnet service is enabled in the RouterOS configuration.")
    if default_snmp_community:
        findings.append("Default SNMP community string is configured.")
    return findings


def _fortinet_findings(config_text: str) -> list[str]:
    findings = []
    if re.search(
        r"^\s*set\s+admin-telnet\s+enable\b",
        config_text,
        re.IGNORECASE | re.MULTILINE,
    ):
        findings.append("Administrative Telnet access is enabled in the FortiOS configuration.")

    snmp_block = _FORTINET_SNMP_BLOCK.search(config_text)
    if snmp_block and any(
        _FORTINET_COMMUNITY.match(line) and _DEFAULT_COMMUNITY.search(line)
        for line in snmp_block.group(1).splitlines()
    ):
        findings.append("Default SNMP community string is configured.")
    return findings


def security_check(config_text: str, device_type: str | None = None) -> list[str]:
    """Scan normalized text output using security checks relevant to its vendor."""
    platform = _platform_name(device_type, config_text)
    config_lines = config_text.splitlines()
    findings: list[str] = []

    if platform.startswith(("cisco_ios", "cisco_xe", "cisco_nxos")):
        has_password_encryption = any(
            re.match(r"^\s*service\s+password-encryption\s*$", line, re.IGNORECASE)
            for line in config_lines
        )
        if not has_password_encryption:
            findings.append("service password-encryption is missing.")
        if _cisco_vty_telnet(config_lines):
            findings.append("Telnet is allowed on a VTY line; use SSH only.")
        if any(_CISCO_SNMP.match(line) for line in config_lines):
            findings.append("Default SNMP community string is configured.")
    elif platform.startswith("juniper"):
        findings.extend(_junos_findings(config_text))
    elif platform.startswith("mikrotik"):
        findings.extend(_routeros_findings(config_text))
    elif platform.startswith("fortinet"):
        findings.extend(_fortinet_findings(config_text))
    else:
        if any(_CISCO_SNMP.match(line) or _JUNIPER_SET_SNMP.match(line) for line in config_lines):
            findings.append("Default SNMP community string is configured.")
        if any(_ROUTEROS_COMMUNITY.search(line) for line in config_lines):
            findings.append("Default SNMP community string is configured.")

    return list(dict.fromkeys(findings))