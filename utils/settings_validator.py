"""Validation helpers for room-level CLI settings."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

# Allowed values per implementation plan v1.6
ALLOWED_VALUES: Dict[str, Dict[str, List[str]]] = {
    "claude": {
        "model": ["sonnet", "opus", "haiku"],
        "permission_mode": ["default", "ask", "deny"],
        "tools": [
            "Bash",
            "Edit",
            "Read",
            "Write",
            "Grep",
            "Glob",
            "Task",
            "WebFetch",
            "WebSearch",
            "NotebookEdit",
            "TodoWrite",
            "SlashCommand",
            "Skill",
        ],
    },
    "codex": {
        "model": ["gpt-5.1", "gpt-5.1-codex", "gpt-5.1-codex-mini", "gpt-5.1-codex-max"],
        "sandbox": ["read-only", "workspace-write", "danger-full-access"],
        "approval_policy": ["untrusted", "on-failure", "on-request", "never"],
        "reasoning_effort": ["low", "medium", "high", "extra-high"],
    },
    "gemini": {
        "model": ["gemini-3.0-pro", "gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-2.0-flash"],
        "approval_mode": ["default", "auto_edit", "yolo"],
    },
}

# Reserved options that must not be passed via custom_flags
RESERVED_FLAGS: Dict[str, List[str]] = {
    "claude": ["--model", "--permission-mode", "--tools"],
    "codex": ["-m", "--model", "-s", "--sandbox", "-a", "--ask-for-approval", "-r", "--reasoning-effort"],
    "gemini": ["-m", "--model", "-s", "--sandbox", "-y", "--yolo", "--approval-mode"],
}

DANGEROUS_FLAGS = [
    "--exec",
    "--eval",
    "--unsafe",
    "--allow-root",
    "--disable-sandbox",
    "--no-verify",
    "--rm",
    "--delete",
]

SHELL_META_CHARS = [";", "|", "&", "$", "`", "(", ")", "<", ">", "\n", "\r"]


class ValidationError(ValueError):
    """Raised when settings validation fails."""


def _validate_flag_name(flag: str, reserved: List[str]) -> None:
    flag_name = flag.split("=")[0].split()[0]
    if flag_name in reserved:
        raise ValidationError(
            f"Reserved flag cannot be used in custom_flags: {flag_name}. Use dedicated fields instead."
        )


def validate_custom_flags(flags: List[str], ai_type: str) -> None:
    if len(flags) > 10:
        raise ValidationError("Too many custom flags (max 10)")

    reserved = RESERVED_FLAGS.get(ai_type, [])

    for flag in flags:
        if not flag.startswith("-"):
            raise ValidationError(f"Invalid flag format: {flag}")
        if len(flag) > 100:
            raise ValidationError(f"Flag too long: {flag}")
        _validate_flag_name(flag, reserved)
        if any(d in flag.lower() for d in DANGEROUS_FLAGS):
            raise ValidationError(f"Dangerous flag detected: {flag}")
        if any(char in flag for char in SHELL_META_CHARS):
            raise ValidationError(f"Invalid character in flag: {flag}")


def _validate_section(section: Dict[str, Any], ai_type: str) -> Dict[str, Any]:
    allowed = ALLOWED_VALUES[ai_type]
    result: Dict[str, Any] = {}

    # model
    if "model" in section:
        model = section["model"]
        if model not in allowed["model"]:
            raise ValidationError(f"Invalid model for {ai_type}: {model}")
        result["model"] = model

    # permission_mode / sandbox / approval_policy / reasoning_effort
    for key in ("permission_mode", "sandbox", "approval_policy", "reasoning_effort"):
        if key in section:
            value = section[key]
            if key not in allowed:
                raise ValidationError(f"Unsupported field for {ai_type}: {key}")
            if value not in allowed[key]:
                raise ValidationError(f"Invalid {key} for {ai_type}: {value}")
            result[key] = value

    # tools
    if "tools" in section:
        tools = section["tools"]
        if not isinstance(tools, list):
            raise ValidationError("tools must be a list")
        for tool in tools:
            if tool not in allowed["tools"]:
                raise ValidationError(f"Invalid tool for {ai_type}: {tool}")
        result["tools"] = tools

    # custom_flags
    if "custom_flags" in section:
        flags = section["custom_flags"]
        if not isinstance(flags, list):
            raise ValidationError("custom_flags must be a list")
        validate_custom_flags(flags, ai_type)
        result["custom_flags"] = flags

    # v4.6: allowed_tools / disallowed_tools (claude only, free-form patterns)
    if ai_type == "claude":
        for key in ("allowed_tools", "disallowed_tools"):
            if key in section:
                value = section[key]
                if not isinstance(value, list):
                    raise ValidationError(f"{key} must be a list")
                # Validate each pattern is a non-empty string, max 100 chars
                for pattern in value:
                    if not isinstance(pattern, str) or not pattern:
                        raise ValidationError(f"Invalid pattern in {key}: must be non-empty string")
                    if len(pattern) > 100:
                        raise ValidationError(f"Pattern too long in {key}: {pattern[:20]}...")
                result[key] = value

    return result


def _validate_gemini_section(section: Dict[str, Any]) -> Dict[str, Any]:
    """Validate gemini-specific settings."""
    allowed = ALLOWED_VALUES["gemini"]
    result: Dict[str, Any] = {}

    # model
    if "model" in section:
        model = section["model"]
        if model not in allowed["model"]:
            raise ValidationError(f"Invalid model for gemini: {model}")
        result["model"] = model

    # approval_mode
    if "approval_mode" in section:
        value = section["approval_mode"]
        if value not in allowed["approval_mode"]:
            raise ValidationError(f"Invalid approval_mode for gemini: {value}")
        result["approval_mode"] = value

    # sandbox (boolean)
    if "sandbox" in section:
        value = section["sandbox"]
        if not isinstance(value, bool):
            raise ValidationError("gemini sandbox must be a boolean")
        result["sandbox"] = value

    # yolo (boolean)
    if "yolo" in section:
        value = section["yolo"]
        if not isinstance(value, bool):
            raise ValidationError("gemini yolo must be a boolean")
        result["yolo"] = value

    # custom_flags
    if "custom_flags" in section:
        flags = section["custom_flags"]
        if not isinstance(flags, list):
            raise ValidationError("custom_flags must be a list")
        validate_custom_flags(flags, "gemini")
        result["custom_flags"] = flags

    return result


def validate_settings(settings: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Validate and sanitize settings structure.

    Returns sanitized dict (whitelisted keys only) or None.
    Raises ValidationError on invalid structure or values.
    """

    if settings is None:
        return None
    if not isinstance(settings, dict):
        raise ValidationError("Settings must be an object")

    sanitized: Dict[str, Any] = {}

    if "claude" in settings:
        if not isinstance(settings["claude"], dict):
            raise ValidationError("claude settings must be an object")
        sanitized["claude"] = _validate_section(settings["claude"], "claude")

    if "codex" in settings:
        if not isinstance(settings["codex"], dict):
            raise ValidationError("codex settings must be an object")
        sanitized["codex"] = _validate_section(settings["codex"], "codex")

    if "gemini" in settings:
        if not isinstance(settings["gemini"], dict):
            raise ValidationError("gemini settings must be an object")
        sanitized["gemini"] = _validate_gemini_section(settings["gemini"])

    # ignore unknown top-level keys (whitelist policy)
    return sanitized


def parse_settings_json(raw: str) -> Optional[Dict[str, Any]]:
    """Parse JSON string to dict or None.

    Raises ValidationError on JSON decode errors.
    """

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValidationError(f"Invalid JSON: {exc.msg}") from exc
    return parsed if parsed is not None else None
