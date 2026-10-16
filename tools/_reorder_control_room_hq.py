"""One-shot restructure of control_room.html for HQ Attention layout."""
from __future__ import annotations

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "templates" / "control_room.html"
text = path.read_text(encoding="utf-8")

stat_start = text.find('    <div class="statbar">')
stat_end = text.find('    <div class="main">', stat_start)
if stat_start < 0 or stat_end < 0:
    raise SystemExit(f"statbar markers missing {stat_start=} {stat_end=}")
hq_include = '    {% include "_control_room_hq.html" %}\n\n'
text = text[:stat_start] + hq_include + text[stat_end:]

main_start = text.find('    <div class="main">')
main_end = text.find("\n    </div>\n\n    <script>\n        // ── CSRF", main_start)
if main_start < 0 or main_end < 0:
    raise SystemExit(f"main markers missing {main_start=} {main_end=}")

main_block = text[main_start:main_end]
inner_open = main_block.find(">", main_block.find('<div class="main"')) + 1
inner = main_block[inner_open:]

flash_marker = "{% with messages = get_flashed_messages"
breach_marker = "        <!-- Breach Intel Panel -->"
client_marker = "        <!-- Client list -->"

i_flash = inner.find(flash_marker)
i_breach = inner.find(breach_marker)
i_client = inner.find(client_marker)
if min(i_flash, i_breach, i_client) < 0:
    raise SystemExit(f"section markers {i_flash=} {i_breach=} {i_client=}")

flash_sec = inner[i_flash:i_breach]
tools_sec = inner[i_breach:i_client]
work_sec = inner[i_client:]

mitre_start = tools_sec.find("        <!-- MITRE ATT&CK Reference -->")
mitre_end = tools_sec.find("        <!-- Shift checklist -->")
if mitre_start >= 0 and mitre_end > mitre_start:
    mitre = tools_sec[mitre_start:mitre_end]
    tools_sec = (
        tools_sec[:mitre_start]
        + "        {% if not ops_mode %}\n"
        + mitre
        + "        {% endif %}\n"
        + tools_sec[mitre_end:]
    )

tools_sec = tools_sec.replace(
    "earn XP",
    "{% if not ops_mode %}earn XP{% else %}review findings{% endif %}",
)
tools_sec = tools_sec.replace(
    "+25 XP",
    "{% if not ops_mode %}+25 XP{% else %}resolve{% endif %}",
)

tools_wrapped = (
    '        <details class="hq-tools"'
    "{% if not ops_mode %} open{% endif %}>\n"
    "            <summary>Tools · Intel, VPN, Scanner, Agent</summary>\n"
    '            <div class="hq-tools-body">\n'
    + tools_sec
    + "\n            </div>\n"
    "        </details>\n\n"
)

new_inner = flash_sec + work_sec + "\n" + tools_wrapped
new_main = main_block[:inner_open] + new_inner
text = text[:main_start] + new_main + text[main_end:]

text = text.replace(
    "        .panel {\n"
    "            background: #12151f;\n"
    "            border: 1px solid #1e2235;\n"
    "            border-radius: 6px;\n"
    "            overflow: hidden;\n"
    "        }",
    "        .panel {\n"
    "            background: var(--ops-surface, #12151f);\n"
    "            border: 1px solid var(--ops-border, #1e2235);\n"
    "            border-radius: 6px;\n"
    "            overflow: hidden;\n"
    "        }",
)

path.write_text(text, encoding="utf-8")
print("OK", path)
for needle in (
    "_control_room_hq.html",
    "hq-tools",
    "{% if not ops_mode %}",
    "<!-- Client list -->",
    "<!-- Breach Intel Panel -->",
    '<div class="statbar">',
):
    print(f"{needle!r}: {text.count(needle)}")
