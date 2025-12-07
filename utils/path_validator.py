"""Workspace path validation for security."""
import os
from pathlib import Path
from typing import List


def get_default_allowed_paths() -> List[str]:
    """Get default allowed paths based on current user's home directory.

    By default, allows the entire home directory for flexibility.
    Users can restrict this via ALLOWED_BASE_PATHS environment variable.
    """
    home = str(Path.home())
    return [home]


# Allowed base paths for workspace directories
# Override by setting ALLOWED_BASE_PATHS environment variable (comma-separated)
_env_paths = os.environ.get("ALLOWED_BASE_PATHS", "")
ALLOWED_BASE_PATHS: List[str] = (
    [p.strip() for p in _env_paths.split(",") if p.strip()]
    if _env_paths
    else get_default_allowed_paths()
)

FORBIDDEN_PATHS: List[str] = [
    "/System",
    "/Library",
    "/private",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/var",
]


def is_safe_workspace_path(path: str) -> bool:
    """
    Check if a workspace path is safe (within allowed directories and not in forbidden ones).

    Args:
        path: The path to validate

    Returns:
        True if the path is safe, False otherwise
    """
    try:
        abs_path = Path(path).resolve()
        abs_path_str = str(abs_path)

        # Check forbidden paths first
        for forbidden in FORBIDDEN_PATHS:
            if abs_path_str.startswith(forbidden):
                return False

        # Check if path is within allowed base paths
        for allowed in ALLOWED_BASE_PATHS:
            if abs_path_str.startswith(allowed):
                return True

        return False
    except (ValueError, OSError):
        return False


def validate_workspace_path(path: str) -> str:
    """
    Validate and resolve a workspace path.

    Args:
        path: The path to validate

    Returns:
        The resolved absolute path

    Raises:
        ValueError: If the path is not allowed
    """
    if not is_safe_workspace_path(path):
        raise ValueError(f"Workspace path is not allowed: {path}")
    return str(Path(path).resolve())
