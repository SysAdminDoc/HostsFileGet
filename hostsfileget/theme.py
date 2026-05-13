"""GUI palette, WCAG contrast helpers, and the accessibility audit report.

This module is intentionally GUI-free: it only defines the ``PALETTE``
mapping, the contrast-pair fixture, and the pure-Python sRGB math that
produces the audit report. The HostsFileEditor GUI imports ``PALETTE``
to style its widgets and exposes the report through the
**Tools > Accessibility Audit...** dialog and the CLI.
"""

from __future__ import annotations


# A restrained palette keeps the interface calm and scannable. We still use
# colour for priority and state, but most surfaces stay close together so the
# eye lands on structure and content instead of decoration.
PALETTE = {
    "base": "#0f1318",
    "mantle": "#141a20",
    "panel": "#171e26",
    "panel_alt": "#1b2430",
    "crust": "#0c1117",
    "text": "#edf2f7",
    "subtext": "#a0acb8",
    "surface0": "#202935",
    "surface1": "#293444",
    "surface2": "#354255",
    "overlay0": "#5d6977",
    "overlay1": "#7d8896",
    "border": "#273241",
    "focus": "#7ea8ff",
    "ink": "#0b1020",
    "blue": "#8fb2ff",
    "blue_hover": "#a5c1ff",
    "green": "#8fc4a1",
    "green_hover": "#a4d0b3",
    "green_press": "#72b387",
    "red": "#e8a1aa",
    "red_hover": "#efb0b8",
    "red_press": "#d38993",
    "yellow": "#d8c08b",
    "yellow_ink": "#2e2410",
    "warning_highlight": "#a38900",
    "accent": "#8fb2ff",
}

ACCESSIBILITY_CONTRAST_PAIRS = (
    ("Body text", "text", "base", 4.5),
    ("Muted body text", "subtext", "base", 4.5),
    ("Secondary label on panel", "overlay1", "panel", 4.5),
    ("Code surface text", "text", "crust", 4.5),
    ("Focus ring on base", "focus", "base", 3.0),
    ("Action button text", "ink", "blue", 4.5),
    ("Saved button text", "ink", "green", 4.5),
    ("Danger button text", "ink", "red", 4.5),
    ("Warning text", "yellow", "panel", 4.5),
    ("Inline discard warning", "ink", "red_press", 4.5),
    ("Inline transform warning", "ink", "warning_highlight", 4.5),
)


def _resolve_palette_color(color: str, palette: dict[str, str]) -> str:
    return palette.get(color, color)


def _hex_to_srgb(color: str) -> tuple[float, float, float]:
    value = color.strip().lstrip("#")
    if len(value) != 6:
        raise ValueError(f"Expected #RRGGBB color, got {color!r}")
    try:
        return tuple(int(value[index:index + 2], 16) / 255 for index in (0, 2, 4))
    except ValueError as exc:
        raise ValueError(f"Expected #RRGGBB color, got {color!r}") from exc


def _linearize_srgb_channel(channel: float) -> float:
    if channel <= 0.03928:
        return channel / 12.92
    return ((channel + 0.055) / 1.055) ** 2.4


def relative_luminance(color: str) -> float:
    red, green, blue = (_linearize_srgb_channel(channel) for channel in _hex_to_srgb(color))
    return (0.2126 * red) + (0.7152 * green) + (0.0722 * blue)


def contrast_ratio(foreground: str, background: str) -> float:
    fg_luminance = relative_luminance(foreground)
    bg_luminance = relative_luminance(background)
    lighter = max(fg_luminance, bg_luminance)
    darker = min(fg_luminance, bg_luminance)
    return (lighter + 0.05) / (darker + 0.05)


def build_accessibility_audit_report(palette: dict[str, str] | None = None) -> dict:
    palette = palette or PALETTE
    contrast_pairs = []
    for label, fg_key, bg_key, minimum in ACCESSIBILITY_CONTRAST_PAIRS:
        foreground = _resolve_palette_color(fg_key, palette)
        background = _resolve_palette_color(bg_key, palette)
        ratio = contrast_ratio(foreground, background)
        contrast_pairs.append({
            "label": label,
            "foreground": foreground,
            "background": background,
            "ratio": round(ratio, 2),
            "minimum": minimum,
            "passes": ratio >= minimum,
        })

    return {
        "contrast_pairs": contrast_pairs,
        "summary": {
            "total_pairs": len(contrast_pairs),
            "passing_pairs": sum(1 for pair in contrast_pairs if pair["passes"]),
        },
        "font_checks": [
            "Primary UI font uses Segoe UI at 10pt or larger.",
            "Code/editor surfaces use Consolas at 10pt or larger.",
            "Windows DPI awareness is enabled before the Tk root is built.",
        ],
        "assistive_tech_checks": [
            "Primary commands use visible text labels, not icon-only buttons.",
            "Tooltips are supplemental; core actions also have button/menu labels.",
            "Manual Narrator/NVDA checks should cover menu traversal, editor focus, dialogs, and status updates.",
        ],
    }


def format_accessibility_audit_report(report: dict) -> str:
    summary = report.get("summary", {})
    lines = [
        "Accessibility audit",
        f"Contrast pairs: {summary.get('passing_pairs', 0)}/{summary.get('total_pairs', 0)} passing",
        "",
        "Contrast:",
    ]
    for pair in report.get("contrast_pairs", []):
        status = "PASS" if pair.get("passes") else "FAIL"
        lines.append(
            f"  {status} {pair.get('label')}: {pair.get('ratio')}:1 "
            f"(min {pair.get('minimum')}:1, fg {pair.get('foreground')}, bg {pair.get('background')})"
        )
    lines.append("")
    lines.append("Font checks:")
    for item in report.get("font_checks", []):
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("Assistive-technology checks:")
    for item in report.get("assistive_tech_checks", []):
        lines.append(f"  - {item}")
    return "\n".join(lines)


__all__ = [
    "PALETTE",
    "ACCESSIBILITY_CONTRAST_PAIRS",
    "_resolve_palette_color",
    "_hex_to_srgb",
    "_linearize_srgb_channel",
    "relative_luminance",
    "contrast_ratio",
    "build_accessibility_audit_report",
    "format_accessibility_audit_report",
]
