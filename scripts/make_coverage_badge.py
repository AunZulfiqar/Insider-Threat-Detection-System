"""
Generates docs/coverage.svg from coverage.py's own JSON report.

Replaces the third-party `coverage-badge` package, which depends on
`pkg_resources` -- an API setuptools has now removed, breaking `coverage-badge`
on any fresh install. This script has zero extra dependencies beyond
`coverage` itself (already a CI dependency).

Usage (after `coverage run -m pytest`):
    coverage json -o coverage.json
    python scripts/make_coverage_badge.py coverage.json docs/coverage.svg
"""
import json
import sys


def badge_color(pct):
    if pct >= 90:
        return "#4c1"       # bright green
    if pct >= 75:
        return "#97CA00"    # green
    if pct >= 50:
        return "#dfb317"    # yellow
    return "#e05d44"        # red


def make_svg(pct):
    label, value = "coverage", f"{pct:.0f}%"
    label_w, value_w = 61, 8 * len(value) + 15
    total_w = label_w + value_w
    color = badge_color(pct)

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img" aria-label="{label}: {value}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_w}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_w}" height="20" fill="#555"/>
    <rect x="{label_w}" width="{value_w}" height="20" fill="{color}"/>
    <rect width="{total_w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="{label_w / 2:.1f}" y="14">{label}</text>
    <text x="{label_w + value_w / 2:.1f}" y="14">{value}</text>
  </g>
</svg>
'''


def main():
    if len(sys.argv) != 3:
        print("Usage: make_coverage_badge.py <coverage.json> <output.svg>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        data = json.load(f)
    pct = data["totals"]["percent_covered"]

    with open(sys.argv[2], "w") as f:
        f.write(make_svg(pct))

    print(f"Wrote {sys.argv[2]} ({pct:.1f}% coverage)")


if __name__ == "__main__":
    main()
