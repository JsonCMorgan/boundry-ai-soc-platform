"""
playbook_loader.py — Boundry.AI Incident Response Playbook Loader

Discovers and loads YAML playbooks from the playbooks/yaml/ directory.
Used by app.py to render /playbooks and /playbooks/<id> routes.

Adding a new playbook: drop a .yaml file in playbooks/yaml/ — no code changes needed.
"""

import os
import yaml
from functools import lru_cache

_PLAYBOOK_DIR = os.path.join(os.path.dirname(__file__), "playbooks", "yaml")
_MARKDOWN_DIR = os.path.join(os.path.dirname(__file__), "playbooks", "markdown")

# Severity display order for the index page
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _load_yaml_file(path: str) -> dict | None:
    """Load and parse a single YAML playbook file. Returns None on error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if not isinstance(data, dict) or not data.get("id"):
            return None
        return data
    except Exception as exc:
        print(f"[playbooks] Failed to load {path}: {exc}")
        return None


def _markdown_path(playbook_id: str) -> str:
    return os.path.join(_MARKDOWN_DIR, f"{playbook_id}.md")


def _has_markdown(playbook_id: str) -> bool:
    return os.path.isfile(_markdown_path(playbook_id))


def get_all_playbooks() -> list[dict]:
    """
    Return a list of all playbook summary dicts, sorted by severity then title.
    Each item contains the top-level metadata (no phases array — use get_playbook() for that).
    """
    if not os.path.isdir(_PLAYBOOK_DIR):
        return []

    playbooks = []
    for filename in os.listdir(_PLAYBOOK_DIR):
        if not filename.endswith(".yaml"):
            continue
        data = _load_yaml_file(os.path.join(_PLAYBOOK_DIR, filename))
        if not data:
            continue
        playbooks.append({
            "id":           data.get("id"),
            "title":        data.get("title", "Untitled"),
            "icon":         data.get("icon", "📋"),
            "color":        data.get("color", "#666"),
            "severity":     data.get("severity", "MEDIUM"),
            "summary":      (data.get("summary") or "")[:250],
            "phase_count":  len(data.get("phases", [])),
            "has_markdown": _has_markdown(data.get("id", "")),
            "mitre_count":  len(data.get("mitre_techniques", [])),
            "version":      data.get("version", "1.0"),
            "last_updated": data.get("last_updated", ""),
        })

    playbooks.sort(key=lambda p: (
        _SEVERITY_ORDER.get(p["severity"], 99),
        p["title"],
    ))
    return playbooks


def get_playbook(playbook_id: str) -> dict | None:
    """
    Return the full playbook dict for a given ID, including all phases.
    Returns None if not found.
    """
    if not playbook_id or not playbook_id.replace("_", "").isalnum():
        return None  # basic path safety

    path = os.path.join(_PLAYBOOK_DIR, f"{playbook_id}.yaml")
    if not os.path.isfile(path):
        return None

    data = _load_yaml_file(path)
    if not data:
        return None

    data["has_markdown"] = _has_markdown(playbook_id)
    return data


def get_markdown(playbook_id: str) -> str | None:
    """
    Return the raw Markdown text for the business-readable version of a playbook.
    Returns None if not found.
    """
    if not playbook_id or not playbook_id.replace("_", "").isalnum():
        return None

    path = _markdown_path(playbook_id)
    if not os.path.isfile(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except Exception as exc:
        print(f"[playbooks] Failed to read markdown {path}: {exc}")
        return None


def playbooks_by_severity(severity: str) -> list[dict]:
    """Return all playbooks matching a specific severity level."""
    return [p for p in get_all_playbooks() if p["severity"] == severity]


def get_playbook_for_finding(mitre_technique: str) -> list[dict]:
    """
    Given a MITRE technique ID, return all playbooks whose mitre_techniques
    list includes that technique. Used to surface relevant playbooks on
    the finding detail page.
    """
    if not mitre_technique:
        return []

    tid = mitre_technique.upper().strip()
    results = []
    for filename in os.listdir(_PLAYBOOK_DIR) if os.path.isdir(_PLAYBOOK_DIR) else []:
        if not filename.endswith(".yaml"):
            continue
        data = _load_yaml_file(os.path.join(_PLAYBOOK_DIR, filename))
        if not data:
            continue
        technique_ids = [t.get("id", "").upper() for t in data.get("mitre_techniques", [])]
        # Match on full ID or parent technique (T1110 matches T1110.003)
        if any(t == tid or tid.startswith(t + ".") or t.startswith(tid + ".") for t in technique_ids):
            results.append({
                "id":       data["id"],
                "title":    data["title"],
                "icon":     data.get("icon", "📋"),
                "color":    data.get("color", "#666"),
                "severity": data.get("severity", "HIGH"),
            })
    return results
