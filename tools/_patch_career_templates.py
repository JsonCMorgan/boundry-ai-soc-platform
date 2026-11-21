"""Patch hub/case templates for open_url, Next scenario, and tutor include."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "templates"

# Hub: replace static open hrefs with open_url + tutor include
HUBS = [
    ("career_email.html", r'href="/career/email/\{\{ s\.id \}\}"', "href=\"{{ s.open_url }}\"", "s"),
    ("career_intel.html", r'href="/career/intel/\{\{ c\.id \}\}"', "href=\"{{ c.open_url }}\"", "c"),
    ("career_logs.html", r'href="/career/logs/\{\{ d\.id \}\}"', "href=\"{{ d.open_url }}\"", "d"),
    ("career_net.html", r'href="/career/net/\{\{ d\.id \}\}"', "href=\"{{ d.open_url }}\"", "d"),
    ("career_vuln.html", r'href="/career/vuln/\{\{ c\.id \}\}"', "href=\"{{ c.open_url }}\"", "c"),
    ("career_sentinel.html", r'href="/career/sentinel/\{\{ c\.id \}\}"', "href=\"{{ c.open_url }}\"", "c"),
    ("career_entra.html", r'href="/career/entra/\{\{ c\.id \}\}"', "href=\"{{ c.open_url }}\"", "c"),
]

for name, pat, repl, _ in HUBS:
    p = ROOT / name
    t = p.read_text(encoding="utf-8")
    t2, n = re.subn(pat, repl, t)
    if n == 0:
        # try already patched
        if "open_url" not in t:
            raise SystemExit(f"{name}: open href not found")
        print(f"{name}: open_url already")
    else:
        t = t2
        print(f"{name}: open_url patched")
    if "_career_tutor.html" not in t:
        t = t.replace("{% include '_jargon_tooltips.html' %}", "{% include '_career_tutor.html' %}")
        if "_career_tutor.html" not in t:
            t = t.replace("</body>", "  {% include '_career_tutor.html' %}\n</body>")
        print(f"{name}: tutor include")
    p.write_text(t, encoding="utf-8")


NEXT_CSS = """
    .btn-next { border-color: #00ff8866; background: #00ff8818; color: #00ff88; display: none; text-decoration: none; }
    .btn-next.show { display: inline-block; }
"""

NEXT_HTML = """
      <a class="btn btn-next" id="next-scenario" href="{{ next_preview.url if next_preview else '#' }}">Next scenario →</a>
"""

NEXT_JS = """
  function showNext(d) {
    var nb = document.getElementById('next-scenario');
    if (!nb) return;
    if (d && d.next && d.next.url) nb.href = d.next.url;
    nb.classList.add('show');
  }
"""

CASES = [
    "career_email_case.html",
    "career_intel_case.html",
    "career_logs_drill.html",
    "career_net_drill.html",
    "career_vuln_case.html",
    "career_sentinel_case.html",
    "career_entra_case.html",
]

for name in CASES:
    p = ROOT / name
    t = p.read_text(encoding="utf-8")
    if "btn-next" not in t:
        # inject CSS before </style>
        if ".btn-next" not in t:
            t = t.replace("</style>", NEXT_CSS + "</style>", 1)
        # inject next button after result div
        if 'id="result"' in t and "next-scenario" not in t:
            t = re.sub(
                r'(<div class="result" id="result"></div>)',
                r'\1' + NEXT_HTML,
                t,
                count=1,
            )
        # inject showNext function
        if "function showNext" not in t:
            # after CSRF var or first script var
            t = re.sub(
                r"(var CSRF = .*?;\n)",
                r"\1" + NEXT_JS,
                t,
                count=1,
            )
            if "function showNext" not in t:
                t = t.replace("<script>\n", "<script>\n" + NEXT_JS, 1)
        # call showNext after successful grade display
        if "showNext(d)" not in t:
            # after borderColor assignment or el.textContent = lines
            t2 = re.sub(
                r"(el\.style\.borderColor = d\.passed[^;]+;)",
                r"\1\n      showNext(d);",
                t,
                count=1,
            )
            if t2 == t:
                t2 = re.sub(
                    r"(el\.textContent = lines\.join\('\\n'\);)",
                    r"\1\n      showNext(d);",
                    t,
                    count=1,
                )
            t = t2
            if "showNext(d)" not in t:
                print(f"WARN {name}: could not wire showNext call")
        print(f"{name}: next scenario wired")
    else:
        print(f"{name}: next already")

    if "_career_tutor.html" not in t:
        t = t.replace("{% include '_jargon_tooltips.html' %}", "{% include '_career_tutor.html' %}")
        if "_career_tutor.html" not in t:
            t = t.replace("</body>", "  {% include '_career_tutor.html' %}\n</body>")
        print(f"{name}: tutor include")
    p.write_text(t, encoding="utf-8")

# Shift hub tutor if present
shift = ROOT / "career_shift.html"
if shift.exists():
    t = shift.read_text(encoding="utf-8")
    if "_career_tutor.html" not in t:
        # ensure tutor_track can be set — routes may not pass it; partial defaults to spl
        # Add before </body>
        if "{% set tutor_track" not in t:
            t = t.replace(
                "</body>",
                "{% set tutor_track = 'shift' %}\n{% set tutor_context = {'lab': 'shift', 'title': 'Shift Simulation'} %}\n{% include '_career_tutor.html' %}\n</body>",
            )
        else:
            t = t.replace("</body>", "  {% include '_career_tutor.html' %}\n</body>")
        shift.write_text(t, encoding="utf-8")
        print("career_shift.html: tutor include")
    else:
        print("career_shift.html: tutor already")

print("DONE")
