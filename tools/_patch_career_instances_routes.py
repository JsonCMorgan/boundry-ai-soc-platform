"""One-shot patcher: wire variants + tutor context on remaining career lab routes."""
from __future__ import annotations

from pathlib import Path

path = Path(__file__).resolve().parents[1] / "app.py"
text = path.read_text(encoding="utf-8")


def must_replace(src: str, old: str, new: str, label: str) -> str:
    if old not in src:
        raise SystemExit(f"MISSING BLOCK: {label}")
    return src.replace(old, new, 1)


def attach_next(src: str, xp_key_fragment: str, next_expr: str, label: str) -> str:
    """Insert result['next'] before return jsonify in a grade handler."""
    # Find unique xp award block ending with result["xp"] = xp_result / return jsonify
    needle = f'XP_REWARDS["{xp_key_fragment}"]'
    idx = src.find(needle)
    if idx < 0:
        raise SystemExit(f"MISSING XP KEY: {label} ({xp_key_fragment})")
    end = src.find('result["xp"] = xp_result\n    return jsonify(result)', idx)
    if end < 0:
        # already patched?
        if f"result[\"next\"] = {next_expr}" in src[idx : idx + 800]:
            print(f"skip next (already): {label}")
            return src
        raise SystemExit(f"MISSING grade end: {label}")
    insert_at = end + len('result["xp"] = xp_result\n')
    addition = f'    result["next"] = {next_expr}\n'
    return src[:insert_at] + addition + src[insert_at:]


# EMAIL hub+case
text = must_replace(
    text,
    '''    return render_template(
        "career_email.html",
        track_title=email_lab.TRACK_TITLE,
        track_blurb=email_lab.TRACK_BLURB,
        primer=email_lab.PRIMER,
        samples=email_lab.list_samples(),
        best_by_sample=best,
        csrf_token=generate_csrf(),
    )


@app.route("/career/email/<sample_id>")
@analyst_required
def career_email_case(sample_id: str):
    """One email sample with checklist + disposition prove-it."""
    sample = email_lab.get_sample(sample_id)
    if not sample:
        abort(404)
    public = {
        "id": sample["id"],
        "title": sample["title"],
        "difficulty": sample["difficulty"],
        "teach": sample["teach"],
        "raw": sample["raw"],
    }
    return render_template(
        "career_email_case.html",
        sample=public,
        checklist=email_lab.CHECKLIST_ITEMS,
        dispositions=email_lab.DISPOSITIONS,
        csrf_token=generate_csrf(),
    )''',
    '''    samples = career_instances.attach_open_urls(email_lab.list_samples(), "/career/email")
    return render_template(
        "career_email.html",
        track_title=email_lab.TRACK_TITLE,
        track_blurb=email_lab.TRACK_BLURB,
        primer=email_lab.PRIMER,
        samples=samples,
        best_by_sample=best,
        tutor_track="email",
        tutor_context={"lab": "email", "title": email_lab.TRACK_TITLE},
        csrf_token=generate_csrf(),
    )


@app.route("/career/email/<sample_id>")
@analyst_required
def career_email_case(sample_id: str):
    """One email sample with checklist + disposition prove-it (variant via ?seed=)."""
    seed = request.args.get("seed")
    if not seed:
        return redirect(f"/career/email/{sample_id}?seed={career_instances.new_seed()}")
    sample = email_lab.materialize_sample(sample_id, seed)
    if not sample:
        abort(404)
    public = {
        "id": sample["id"],
        "title": sample["title"],
        "difficulty": sample["difficulty"],
        "teach": sample["teach"],
        "raw": sample["raw"],
        "instance_seed": sample.get("instance_seed") or seed,
    }
    tutor_ctx = {
        "lab": "email",
        "case_id": sample["id"],
        "title": sample["title"],
        "teach": sample["teach"],
        "raw": sample["raw"],
    }
    return render_template(
        "career_email_case.html",
        sample=public,
        checklist=email_lab.CHECKLIST_ITEMS,
        dispositions=email_lab.DISPOSITIONS,
        next_preview=email_lab.next_after(sample_id),
        tutor_track="email",
        tutor_lesson_id=sample_id,
        tutor_context=tutor_ctx,
        csrf_token=generate_csrf(),
    )''',
    "email hub+case",
)
text = attach_next(text, "email_triage", "email_lab.next_after(sample_id)", "email grade")
print("email ok")

# LOGS
text = must_replace(
    text,
    '''    return render_template(
        "career_logs.html",
        track_title=log_lab.TRACK_TITLE,
        track_blurb=log_lab.TRACK_BLURB,
        primer=log_lab.PRIMER,
        flashcards=log_lab.FLASHCARDS,
        drills=log_lab.list_drills(),
        best_by_drill=best,
        csrf_token=generate_csrf(),
    )


@app.route("/career/logs/<drill_id>")
@analyst_required
def career_logs_drill(drill_id: str):
    """One log literacy drill with snippet + prove-it grade."""
    drill = log_lab.get_drill(drill_id)
    if not drill:
        abort(404)
    public = {
        "id": drill["id"],
        "title": drill["title"],
        "difficulty": drill["difficulty"],
        "teach": drill["teach"],
        "snippet": drill["snippet"],
    }
    return render_template(
        "career_logs_drill.html",
        drill=public,
        sources=log_lab.SOURCES,
        evidence_types=log_lab.EVIDENCE_TYPES,
        checklist=log_lab.CHECKLIST_ITEMS,
        csrf_token=generate_csrf(),
    )''',
    '''    drills = career_instances.attach_open_urls(log_lab.list_drills(), "/career/logs")
    return render_template(
        "career_logs.html",
        track_title=log_lab.TRACK_TITLE,
        track_blurb=log_lab.TRACK_BLURB,
        primer=log_lab.PRIMER,
        flashcards=log_lab.FLASHCARDS,
        drills=drills,
        best_by_drill=best,
        tutor_track="logs",
        tutor_context={"lab": "logs", "title": log_lab.TRACK_TITLE},
        csrf_token=generate_csrf(),
    )


@app.route("/career/logs/<drill_id>")
@analyst_required
def career_logs_drill(drill_id: str):
    """One log literacy drill with snippet + prove-it grade (variant via ?seed=)."""
    seed = request.args.get("seed")
    if not seed:
        return redirect(f"/career/logs/{drill_id}?seed={career_instances.new_seed()}")
    drill = log_lab.materialize_drill(drill_id, seed)
    if not drill:
        abort(404)
    public = {
        "id": drill["id"],
        "title": drill["title"],
        "difficulty": drill["difficulty"],
        "teach": drill["teach"],
        "snippet": drill["snippet"],
        "instance_seed": drill.get("instance_seed") or seed,
    }
    tutor_ctx = {
        "lab": "logs",
        "case_id": drill["id"],
        "title": drill["title"],
        "teach": drill["teach"],
        "snippet": drill["snippet"],
    }
    return render_template(
        "career_logs_drill.html",
        drill=public,
        sources=log_lab.SOURCES,
        evidence_types=log_lab.EVIDENCE_TYPES,
        checklist=log_lab.CHECKLIST_ITEMS,
        next_preview=log_lab.next_after(drill_id),
        tutor_track="logs",
        tutor_lesson_id=drill_id,
        tutor_context=tutor_ctx,
        csrf_token=generate_csrf(),
    )''',
    "logs hub+drill",
)
text = attach_next(text, "logs_drill", "log_lab.next_after(drill_id)", "logs grade")
print("logs ok")

# INTEL
text = must_replace(
    text,
    '''    return render_template(
        "career_intel.html",
        track_title=intel_lab.TRACK_TITLE,
        track_blurb=intel_lab.TRACK_BLURB,
        primer=intel_lab.PRIMER,
        cases=intel_lab.list_cases(),
        best_by_case=best,
        csrf_token=generate_csrf(),
    )


@app.route("/career/intel/<case_id>")
@analyst_required
def career_intel_case(case_id: str):
    """One IOC enrichment case with lookup + ticket note prove-it."""
    case = intel_lab.get_case(case_id)
    if not case:
        abort(404)
    public = {
        "id": case["id"],
        "title": case["title"],
        "difficulty": case["difficulty"],
        "ioc": case["ioc"],
        "scenario": case["scenario"],
        "teach": case["teach"],
    }
    return render_template(
        "career_intel_case.html",
        case=public,
        checklist=intel_lab.CHECKLIST_ITEMS,
        dispositions=intel_lab.DISPOSITIONS,
        csrf_token=generate_csrf(),
    )''',
    '''    cases = career_instances.attach_open_urls(intel_lab.list_cases(), "/career/intel")
    return render_template(
        "career_intel.html",
        track_title=intel_lab.TRACK_TITLE,
        track_blurb=intel_lab.TRACK_BLURB,
        primer=intel_lab.PRIMER,
        cases=cases,
        best_by_case=best,
        tutor_track="intel",
        tutor_context={"lab": "intel", "title": intel_lab.TRACK_TITLE},
        csrf_token=generate_csrf(),
    )


@app.route("/career/intel/<case_id>")
@analyst_required
def career_intel_case(case_id: str):
    """One IOC enrichment case with lookup + ticket note (variant via ?seed=)."""
    seed = request.args.get("seed")
    if not seed:
        return redirect(f"/career/intel/{case_id}?seed={career_instances.new_seed()}")
    case = intel_lab.materialize_case(case_id, seed)
    if not case:
        abort(404)
    public = {
        "id": case["id"],
        "title": case["title"],
        "difficulty": case["difficulty"],
        "ioc": case["ioc"],
        "scenario": case["scenario"],
        "teach": case["teach"],
        "instance_seed": case.get("instance_seed") or seed,
    }
    tutor_ctx = {
        "lab": "intel",
        "case_id": case["id"],
        "title": case["title"],
        "ioc": case["ioc"],
        "scenario": case["scenario"],
        "teach": case["teach"],
    }
    return render_template(
        "career_intel_case.html",
        case=public,
        checklist=intel_lab.CHECKLIST_ITEMS,
        dispositions=intel_lab.DISPOSITIONS,
        next_preview=intel_lab.next_after(case_id),
        tutor_track="intel",
        tutor_lesson_id=case_id,
        tutor_context=tutor_ctx,
        csrf_token=generate_csrf(),
    )''',
    "intel hub+case",
)
text = attach_next(text, "intel_enrich", "intel_lab.next_after(case_id)", "intel grade")
print("intel ok")

# NET
text = must_replace(
    text,
    '''    return render_template(
        "career_net.html",
        track_title=net_lab.TRACK_TITLE,
        track_blurb=net_lab.TRACK_BLURB,
        primer=net_lab.PRIMER,
        flashcards=net_lab.FLASHCARDS,
        drills=net_lab.list_drills(),
        best_by_drill=best,
        csrf_token=generate_csrf(),
    )


@app.route("/career/net/<drill_id>")
@analyst_required
def career_net_drill(drill_id: str):
    """One networking drill with traffic snippet + prove-it grade."""
    drill = net_lab.get_drill(drill_id)
    if not drill:
        abort(404)
    public = {
        "id": drill["id"],
        "title": drill["title"],
        "difficulty": drill["difficulty"],
        "teach": drill["teach"],
        "snippet": drill["snippet"],
    }
    return render_template(
        "career_net_drill.html",
        drill=public,
        signals=net_lab.SIGNALS,
        directions=net_lab.DIRECTIONS,
        checklist=net_lab.CHECKLIST_ITEMS,
        csrf_token=generate_csrf(),
    )''',
    '''    drills = career_instances.attach_open_urls(net_lab.list_drills(), "/career/net")
    return render_template(
        "career_net.html",
        track_title=net_lab.TRACK_TITLE,
        track_blurb=net_lab.TRACK_BLURB,
        primer=net_lab.PRIMER,
        flashcards=net_lab.FLASHCARDS,
        drills=drills,
        best_by_drill=best,
        tutor_track="net",
        tutor_context={"lab": "net", "title": net_lab.TRACK_TITLE},
        csrf_token=generate_csrf(),
    )


@app.route("/career/net/<drill_id>")
@analyst_required
def career_net_drill(drill_id: str):
    """One networking drill with traffic snippet + prove-it (variant via ?seed=)."""
    seed = request.args.get("seed")
    if not seed:
        return redirect(f"/career/net/{drill_id}?seed={career_instances.new_seed()}")
    drill = net_lab.materialize_drill(drill_id, seed)
    if not drill:
        abort(404)
    public = {
        "id": drill["id"],
        "title": drill["title"],
        "difficulty": drill["difficulty"],
        "teach": drill["teach"],
        "snippet": drill["snippet"],
        "instance_seed": drill.get("instance_seed") or seed,
    }
    tutor_ctx = {
        "lab": "net",
        "case_id": drill["id"],
        "title": drill["title"],
        "teach": drill["teach"],
        "snippet": drill["snippet"],
    }
    return render_template(
        "career_net_drill.html",
        drill=public,
        signals=net_lab.SIGNALS,
        directions=net_lab.DIRECTIONS,
        checklist=net_lab.CHECKLIST_ITEMS,
        next_preview=net_lab.next_after(drill_id),
        tutor_track="net",
        tutor_lesson_id=drill_id,
        tutor_context=tutor_ctx,
        csrf_token=generate_csrf(),
    )''',
    "net hub+drill",
)
text = attach_next(text, "net_drill", "net_lab.next_after(drill_id)", "net grade")
print("net ok")

# VULN
text = must_replace(
    text,
    '''    return render_template(
        "career_vuln.html",
        track_title=vuln_lab.TRACK_TITLE,
        track_blurb=vuln_lab.TRACK_BLURB,
        primer=vuln_lab.PRIMER,
        cases=vuln_lab.list_cases(),
        best_by_case=best,
        csrf_token=generate_csrf(),
    )


@app.route("/career/vuln/<case_id>")
@analyst_required
def career_vuln_case(case_id: str):
    """One vuln triage case with priority + disposition prove-it."""
    case = vuln_lab.get_case(case_id)
    if not case:
        abort(404)
    public = {
        "id": case["id"],
        "title": case["title"],
        "difficulty": case["difficulty"],
        "finding": case["finding"],
        "teach": case["teach"],
    }
    return render_template(
        "career_vuln_case.html",
        case=public,
        priorities=vuln_lab.PRIORITIES,
        dispositions=vuln_lab.DISPOSITIONS,
        checklist=vuln_lab.CHECKLIST_ITEMS,
        csrf_token=generate_csrf(),
    )''',
    '''    cases = career_instances.attach_open_urls(vuln_lab.list_cases(), "/career/vuln")
    return render_template(
        "career_vuln.html",
        track_title=vuln_lab.TRACK_TITLE,
        track_blurb=vuln_lab.TRACK_BLURB,
        primer=vuln_lab.PRIMER,
        cases=cases,
        best_by_case=best,
        tutor_track="vuln",
        tutor_context={"lab": "vuln", "title": vuln_lab.TRACK_TITLE},
        csrf_token=generate_csrf(),
    )


@app.route("/career/vuln/<case_id>")
@analyst_required
def career_vuln_case(case_id: str):
    """One vuln triage case with priority + disposition (variant via ?seed=)."""
    seed = request.args.get("seed")
    if not seed:
        return redirect(f"/career/vuln/{case_id}?seed={career_instances.new_seed()}")
    case = vuln_lab.materialize_case(case_id, seed)
    if not case:
        abort(404)
    public = {
        "id": case["id"],
        "title": case["title"],
        "difficulty": case["difficulty"],
        "finding": case["finding"],
        "teach": case["teach"],
        "instance_seed": case.get("instance_seed") or seed,
    }
    tutor_ctx = {
        "lab": "vuln",
        "case_id": case["id"],
        "title": case["title"],
        "finding": case["finding"],
        "teach": case["teach"],
    }
    return render_template(
        "career_vuln_case.html",
        case=public,
        priorities=vuln_lab.PRIORITIES,
        dispositions=vuln_lab.DISPOSITIONS,
        checklist=vuln_lab.CHECKLIST_ITEMS,
        next_preview=vuln_lab.next_after(case_id),
        tutor_track="vuln",
        tutor_lesson_id=case_id,
        tutor_context=tutor_ctx,
        csrf_token=generate_csrf(),
    )''',
    "vuln hub+case",
)
text = attach_next(text, "vuln_triage", "vuln_lab.next_after(case_id)", "vuln grade")
print("vuln ok")

# SENTINEL
text = must_replace(
    text,
    '''    return render_template(
        "career_sentinel.html",
        track_title=sentinel_lab.TRACK_TITLE,
        track_blurb=sentinel_lab.TRACK_BLURB,
        primer=sentinel_lab.PRIMER,
        cases=sentinel_lab.list_cases(),
        best_by_case=best,
        csrf_token=generate_csrf(),
    )


@app.route("/career/sentinel/<case_id>")
@analyst_required
def career_sentinel_case(case_id: str):
    """One Sentinel workspace case with three blades + prove-it grade."""
    case = sentinel_lab.get_case(case_id)
    if not case:
        abort(404)
    hunt = case["hunt"]
    hunt_cols: list[str] = []
    if hunt.get("rows"):
        hunt_cols = list(hunt["rows"][0].keys())
    public = {
        "id": case["id"],
        "title": case["title"],
        "difficulty": case["difficulty"],
        "client": case["client"],
        "teach": case["teach"],
    }
    return render_template(
        "career_sentinel_case.html",
        case=public,
        incident=case["incident"],
        entities=case["entities"],
        hunt=hunt,
        hunt_cols=hunt_cols,
        blades=sentinel_lab.BLADES,
        dispositions=sentinel_lab.DISPOSITIONS,
        checklist=sentinel_lab.CHECKLIST_ITEMS,
        csrf_token=generate_csrf(),
    )''',
    '''    cases = career_instances.attach_open_urls(sentinel_lab.list_cases(), "/career/sentinel")
    return render_template(
        "career_sentinel.html",
        track_title=sentinel_lab.TRACK_TITLE,
        track_blurb=sentinel_lab.TRACK_BLURB,
        primer=sentinel_lab.PRIMER,
        cases=cases,
        best_by_case=best,
        tutor_track="sentinel",
        tutor_context={"lab": "sentinel", "title": sentinel_lab.TRACK_TITLE},
        csrf_token=generate_csrf(),
    )


@app.route("/career/sentinel/<case_id>")
@analyst_required
def career_sentinel_case(case_id: str):
    """One Sentinel workspace case with three blades (variant via ?seed=)."""
    seed = request.args.get("seed")
    if not seed:
        return redirect(f"/career/sentinel/{case_id}?seed={career_instances.new_seed()}")
    case = sentinel_lab.materialize_case(case_id, seed)
    if not case:
        abort(404)
    hunt = case["hunt"]
    hunt_cols: list[str] = []
    if hunt.get("rows"):
        hunt_cols = list(hunt["rows"][0].keys())
    public = {
        "id": case["id"],
        "title": case["title"],
        "difficulty": case["difficulty"],
        "client": case["client"],
        "teach": case["teach"],
        "instance_seed": case.get("instance_seed") or seed,
    }
    tutor_ctx = {
        "lab": "sentinel",
        "case_id": case["id"],
        "title": case["title"],
        "client": case["client"],
        "teach": case["teach"],
        "incident": case["incident"],
        "entities": case["entities"],
        "hunt": hunt,
    }
    return render_template(
        "career_sentinel_case.html",
        case=public,
        incident=case["incident"],
        entities=case["entities"],
        hunt=hunt,
        hunt_cols=hunt_cols,
        blades=sentinel_lab.BLADES,
        dispositions=sentinel_lab.DISPOSITIONS,
        checklist=sentinel_lab.CHECKLIST_ITEMS,
        next_preview=sentinel_lab.next_after(case_id),
        tutor_track="sentinel",
        tutor_lesson_id=case_id,
        tutor_context=tutor_ctx,
        csrf_token=generate_csrf(),
    )''',
    "sentinel hub+case",
)
text = attach_next(text, "sentinel_triage", "sentinel_lab.next_after(case_id)", "sentinel grade")
print("sentinel ok")

# ENTRA — read current case template kwargs from file snippet
import re

m = re.search(
    r'@app\.route\("/career/entra/<case_id>"\).*?return render_template\(\n'
    r'        "career_entra_case\.html",(.*?)\n    \)\n\n\n@app\.route\("/api/career/entra/grade"',
    text,
    re.S,
)
if not m:
    raise SystemExit("MISSING entra case render block")
print("entra case kwargs preview:", m.group(1)[:300])

text = must_replace(
    text,
    '''    return render_template(
        "career_entra.html",
        track_title=entra_lab.TRACK_TITLE,
        track_blurb=entra_lab.TRACK_BLURB,
        primer=entra_lab.PRIMER,
        cases=entra_lab.list_cases(),
        best_by_case=best,
        csrf_token=generate_csrf(),
    )


@app.route("/career/entra/<case_id>")
@analyst_required
def career_entra_case(case_id: str):
    """One Entra CA storyboard with prove-it grade."""
    case = entra_lab.get_case(case_id)
    if not case:
        abort(404)''',
    '''    cases = career_instances.attach_open_urls(entra_lab.list_cases(), "/career/entra")
    return render_template(
        "career_entra.html",
        track_title=entra_lab.TRACK_TITLE,
        track_blurb=entra_lab.TRACK_BLURB,
        primer=entra_lab.PRIMER,
        cases=cases,
        best_by_case=best,
        tutor_track="entra",
        tutor_context={"lab": "entra", "title": entra_lab.TRACK_TITLE},
        csrf_token=generate_csrf(),
    )


@app.route("/career/entra/<case_id>")
@analyst_required
def career_entra_case(case_id: str):
    """One Entra CA storyboard with prove-it grade (variant via ?seed=)."""
    seed = request.args.get("seed")
    if not seed:
        return redirect(f"/career/entra/{case_id}?seed={career_instances.new_seed()}")
    case = entra_lab.materialize_case(case_id, seed)
    if not case:
        abort(404)''',
    "entra hub+case start",
)

# Replace entra public + render (after materialize already in place for get_case path)
# After our replace, we still have old public= from get_case body — need to fix remainder
old_entra_body = '''    public = {
        "id": case["id"],
        "title": case["title"],
        "difficulty": case["difficulty"],
        "client": case["client"],
        "teach": case["teach"],
    }
    return render_template(
        "career_entra_case.html",
        case=public,
        sb=case["storyboard"],
        outcomes=entra_lab.OUTCOMES,
        dispositions=entra_lab.DISPOSITIONS,
        checklist=entra_lab.CHECKLIST_ITEMS,
        csrf_token=generate_csrf(),
    )'''

if old_entra_body not in text:
    i = text.find("def career_entra_case")
    print(text[i : i + 1200])
    raise SystemExit("entra body pattern mismatch")

text = must_replace(
    text,
    old_entra_body,
    '''    public = {
        "id": case["id"],
        "title": case["title"],
        "difficulty": case["difficulty"],
        "client": case["client"],
        "teach": case["teach"],
        "instance_seed": case.get("instance_seed") or seed,
    }
    sb = case["storyboard"]
    tutor_ctx = {
        "lab": "entra",
        "case_id": case["id"],
        "title": case["title"],
        "client": case["client"],
        "teach": case["teach"],
        "storyboard": sb,
        "alert_text": sb.get("alert_text") if isinstance(sb, dict) else "",
    }
    return render_template(
        "career_entra_case.html",
        case=public,
        sb=sb,
        outcomes=entra_lab.OUTCOMES,
        dispositions=entra_lab.DISPOSITIONS,
        checklist=entra_lab.CHECKLIST_ITEMS,
        next_preview=entra_lab.next_after(case_id),
        tutor_track="entra",
        tutor_lesson_id=case_id,
        tutor_context=tutor_ctx,
        csrf_token=generate_csrf(),
    )''',
    "entra case body",
)

# entra XP key may differ
for key in ("entra_triage", "entra_ca", "entra_drill"):
    if f'XP_REWARDS["{key}"]' in text:
        text = attach_next(text, key, "entra_lab.next_after(case_id)", "entra grade")
        print("entra grade ok via", key)
        break
else:
    raise SystemExit("entra XP key not found")

path.write_text(text, encoding="utf-8")
print("WROTE", path)
