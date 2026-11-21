"""Insert showNext(d) after grade result styling in case templates."""
from __future__ import annotations

import re
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "templates"
files = [
    "career_email_case.html",
    "career_intel_case.html",
    "career_logs_drill.html",
    "career_net_drill.html",
    "career_vuln_case.html",
    "career_sentinel_case.html",
    "career_entra_case.html",
    "career_edr_case.html",
]

for name in files:
    p = root / name
    t = p.read_text(encoding="utf-8")
    if "function showNext" not in t:
        print(name, "NO showNext fn")
        continue
    # Already has a call site besides the function definition
    call_count = len(re.findall(r"showNext\(d\)", t))
    if call_count >= 2 or ("showNext(d);" in t and "function showNext" in t and t.find("showNext(d);") > t.find("function showNext")):
        # edr has call after function; count of showNext(d) may be 2 (def body uses d.next + call)
        if "showNext(d);" in t[t.find("function grade") :]:
            print(name, "OK")
            continue
    t2, n = re.subn(
        r"(el\.style\.borderColor = d\.passed \? '[^']+' : '[^']+';)",
        r"\1\n      showNext(d);",
        t,
        count=1,
    )
    if n:
        p.write_text(t2, encoding="utf-8")
        print(name, "FIXED borderColor")
        continue
    t2, n = re.subn(
        r"(el\.textContent = lines\.join\('\\n'\);)",
        r"\1\n      showNext(d);",
        t,
        count=1,
    )
    if n:
        p.write_text(t2, encoding="utf-8")
        print(name, "FIXED textContent")
    else:
        print(name, "FAIL")
