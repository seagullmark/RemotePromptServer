"""Build CLI command lists for Claude Code and Codex."""
from __future__ import annotations

from typing import Dict, List, Optional


def build_claude_command(settings: Optional[Dict] = None) -> List[str]:
    cmd: List[str] = ["claude", "--print", "--output-format", "text"]

    if settings and "claude" in settings:
        cfg = settings["claude"]
        if "model" in cfg:
            cmd.extend(["--model", cfg["model"]])
        if "permission_mode" in cfg:
            cmd.extend(["--permission-mode", cfg["permission_mode"]])
        if "tools" in cfg:
            tools = ",".join(cfg["tools"])
            cmd.extend(["--tools", tools])
        # v4.6: allowedTools/disallowedTools support
        if "allowed_tools" in cfg and cfg["allowed_tools"]:
            tools = ",".join(cfg["allowed_tools"])
            cmd.extend(["--allowedTools", tools])
        if "disallowed_tools" in cfg and cfg["disallowed_tools"]:
            tools = ",".join(cfg["disallowed_tools"])
            cmd.extend(["--disallowedTools", tools])
        if "custom_flags" in cfg:
            cmd.extend(cfg["custom_flags"])

    return cmd


def build_codex_command(settings: Optional[Dict] = None) -> List[str]:
    cmd: List[str] = ["codex", "exec"]

    if settings and "codex" in settings:
        cfg = settings["codex"]
        if "model" in cfg:
            cmd.extend(["-m", cfg["model"]])
        if "sandbox" in cfg:
            cmd.extend(["-s", cfg["sandbox"]])
        # Note: approval_policy is not supported by codex exec
        # Use --full-auto for automatic execution instead
        if "reasoning_effort" in cfg:
            effort = cfg["reasoning_effort"]
            # Codex 0.63.0+ supports: none, minimal, low, medium, high, xhigh
            # Map extra-high to xhigh for compatibility
            if effort == "extra-high":
                effort = "xhigh"
            cmd.extend(["-c", f"model_reasoning_effort={effort}"])
        if "custom_flags" in cfg:
            cmd.extend(cfg["custom_flags"])

    return cmd


def build_gemini_command(settings: Optional[Dict] = None) -> List[str]:
    """Build Gemini CLI command."""
    cmd: List[str] = ["gemini", "-o", "text"]

    if settings and "gemini" in settings:
        cfg = settings["gemini"]
        if "model" in cfg:
            cmd.extend(["-m", cfg["model"]])
        if "sandbox" in cfg and cfg["sandbox"]:
            cmd.append("-s")
        if "yolo" in cfg and cfg["yolo"]:
            cmd.append("-y")
        if "approval_mode" in cfg:
            cmd.extend(["--approval-mode", cfg["approval_mode"]])
        if "custom_flags" in cfg:
            cmd.extend(cfg["custom_flags"])

    return cmd
