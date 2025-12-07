"""QR code generator for server configuration sharing.

Generates QR codes containing server connection information
that can be scanned by the iOS app for quick setup.
"""
from __future__ import annotations

import base64
import json
import logging
from io import BytesIO
from pathlib import Path
from typing import Optional

import qrcode
from qrcode.constants import ERROR_CORRECT_M

LOGGER = logging.getLogger(__name__)

# Default QR code output path
DEFAULT_QR_PATH = Path("qrcode.png")


def generate_config_payload(
    server_url: str,
    api_key: str,
    fingerprint: str,
    server_name: Optional[str] = None,
    device_id: Optional[str] = None,
) -> str:
    """Generate JSON payload for QR code.

    Matches iOS SettingsShareData format with snake_case keys.

    Args:
        server_url: Full server URL (e.g., https://192.168.1.100:8443)
        api_key: API key for authentication
        fingerprint: SSL certificate fingerprint (SHA256:XX:XX:...)
        server_name: Optional display name for the server
        device_id: Optional device ID (generated on iOS if not provided)

    Returns:
        JSON string containing server configuration
    """
    import uuid

    payload = {
        "server_url": server_url,
        "api_key": api_key,
        "device_id": device_id or str(uuid.uuid4()),
        "alternative_urls": [],
        "auto_fallback": True,
        "certificate_fingerprint": fingerprint,
    }

    return json.dumps(payload, separators=(",", ":"))


def generate_qr_ascii(
    server_url: str,
    api_key: str,
    fingerprint: str,
    server_name: Optional[str] = None,
) -> str:
    """Generate ASCII art QR code for terminal display.

    Args:
        server_url: Full server URL
        api_key: API key for authentication
        fingerprint: SSL certificate fingerprint
        server_name: Optional display name

    Returns:
        ASCII string representation of QR code
    """
    payload = generate_config_payload(server_url, api_key, fingerprint, server_name)

    qr = qrcode.QRCode(
        version=None,  # Auto-size
        error_correction=ERROR_CORRECT_M,
        box_size=1,
        border=1,
    )
    qr.add_data(payload)
    qr.make(fit=True)

    # Generate ASCII representation using Unicode block characters
    # This creates a more compact representation that works in most terminals
    matrix = qr.get_matrix()
    lines = []

    # Process two rows at a time for compact display
    for i in range(0, len(matrix), 2):
        line = ""
        for j in range(len(matrix[0])):
            top = matrix[i][j] if i < len(matrix) else False
            bottom = matrix[i + 1][j] if i + 1 < len(matrix) else False

            if top and bottom:
                line += "█"
            elif top and not bottom:
                line += "▀"
            elif not top and bottom:
                line += "▄"
            else:
                line += " "
        lines.append(line)

    return "\n".join(lines)


def generate_qr_png_base64(
    server_url: str,
    api_key: str,
    fingerprint: str,
    server_name: Optional[str] = None,
) -> str:
    """Generate PNG QR code as base64 string.

    Args:
        server_url: Full server URL
        api_key: API key for authentication
        fingerprint: SSL certificate fingerprint
        server_name: Optional display name

    Returns:
        Base64-encoded PNG image data
    """
    payload = generate_config_payload(server_url, api_key, fingerprint, server_name)

    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)

    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def print_qr_banner(
    server_url: str,
    api_key: str,
    fingerprint: str,
    server_name: Optional[str] = None,
    version: str = "1.0.0",
) -> None:
    """Print startup banner with QR code for easy iOS app setup.

    Args:
        server_url: Full server URL
        api_key: API key for authentication
        fingerprint: SSL certificate fingerprint
        server_name: Optional display name
        version: Server version string
    """
    qr_ascii = generate_qr_ascii(server_url, api_key, fingerprint, server_name)

    # Calculate box width based on QR code width
    qr_lines = qr_ascii.split("\n")
    qr_width = max(len(line) for line in qr_lines) if qr_lines else 40
    box_width = max(qr_width + 4, 64)

    # Truncate fingerprint for display if too long
    fp_display = fingerprint
    if len(fingerprint) > box_width - 4:
        fp_display = fingerprint[:box_width - 7] + "..."

    # Mask API key for security (show first 4 and last 4 chars)
    if len(api_key) > 12:
        api_key_masked = api_key[:4] + "..." + api_key[-4:]
    else:
        api_key_masked = api_key[:2] + "..." if len(api_key) > 4 else "****"

    print()
    print("═" * box_width)
    print(f" RemotePrompt Server v{version}")
    print("═" * box_width)
    print()
    print(f" Server URL: {server_url}")
    print(f" API Key: {api_key_masked}")
    print()
    print(" Certificate Fingerprint:")
    print(f" {fp_display}")
    print()
    print("─" * box_width)
    print(" Scan with RemotePrompt iOS app to connect:")
    print("─" * box_width)
    print()

    # Center the QR code
    for line in qr_lines:
        padding = (box_width - len(line)) // 2
        print(" " * padding + line)

    print()
    print("─" * box_width)
    print(" ※ iOSアプリの「QRコードスキャン」で読み取ってください")
    print("═" * box_width)
    print()

    LOGGER.info("QR code displayed for server: %s", server_url)


def save_qr_png(
    server_url: str,
    api_key: str,
    fingerprint: str,
    server_name: Optional[str] = None,
    output_path: Optional[Path] = None,
) -> Path:
    """Save QR code as PNG file.

    Args:
        server_url: Full server URL
        api_key: API key for authentication
        fingerprint: SSL certificate fingerprint
        server_name: Optional display name
        output_path: Output file path (default: ./qrcode.png)

    Returns:
        Path to the saved QR code image
    """
    output_path = output_path or DEFAULT_QR_PATH
    payload = generate_config_payload(server_url, api_key, fingerprint, server_name)

    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(payload)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img.save(output_path)

    LOGGER.info("QR code saved to: %s", output_path)
    return output_path


def ensure_qr_code_exists(
    server_url: str,
    api_key: str,
    fingerprint: str,
    server_name: Optional[str] = None,
    output_path: Optional[Path] = None,
    force_regenerate: bool = False,
) -> Path:
    """Ensure QR code file exists, generate if needed.

    Regenerates the QR code if:
    - File doesn't exist
    - force_regenerate is True
    - Content would be different (settings changed)

    Args:
        server_url: Full server URL
        api_key: API key for authentication
        fingerprint: SSL certificate fingerprint
        server_name: Optional display name
        output_path: Output file path (default: ./qrcode.png)
        force_regenerate: Force regeneration even if file exists

    Returns:
        Path to the QR code image
    """
    output_path = output_path or DEFAULT_QR_PATH

    if not force_regenerate and output_path.exists():
        # Check if we need to regenerate by comparing payload
        # For simplicity, always regenerate on startup to ensure consistency
        LOGGER.debug("QR code already exists at: %s", output_path)

    return save_qr_png(
        server_url=server_url,
        api_key=api_key,
        fingerprint=fingerprint,
        server_name=server_name,
        output_path=output_path,
    )
