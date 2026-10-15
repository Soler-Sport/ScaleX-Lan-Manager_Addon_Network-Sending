import json
import os
import re


def read_chitu_hook_model_names(ctb_path):
    """Looks for ChituHook/goo_hook's own sidecar JSON next to `ctb_path`
    (same directory, same base name, ".json" extension) and returns its flat
    list of original model file names, or None if there's no sidecar / it
    isn't readable JSON. Best-effort and silent: a missing sidecar (hook
    disabled or not installed - true by default as of 2026-09-24, see
    goo_hook.c's InstallHooksThread, FL_InstallHook() is commented out there
    pending isolated verification after an unrelated crash - or just an
    older/manually-saved file) is the normal case, not an error worth
    logging on every single capture."""
    json_path = os.path.splitext(ctb_path)[0] + ".json"
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            names = json.load(f)
    except (OSError, ValueError):
        return None
    if not isinstance(names, list):
        return None
    return [str(n) for n in names if n]


def _normalize_composition_key(text):
    """Shared by match_composition_components()'s two sides (model name
    stem, component code) - exact match, but tolerant of formatting noise
    that isn't a real difference: case, and whitespace ANYWHERE in the
    string (not just leading/trailing - confirmed live 2026-09-25, real
    model names came back as "WW-35033 _W_R_A.stl" with a space the
    matching warehouse code "WW-35033_W_R_A" doesn't have, so every model
    on that plate went unmatched under a plain .strip())."""
    return re.sub(r"\s+", "", text).lower()


def match_composition_components(model_names, components):
    """Exact match (case-insensitive, whitespace- and extension-stripped) of
    each model file name against a warehouse component - deliberately NOT
    the substring/fuzzy match ScaleX's own browser code uses (see this
    section's module-level comment), since that only ever surfaces one
    guess. Returns (matched, ambiguous, unmatched):

    - matched = list[(component_dict, quantity)], one entry per distinct,
      UNAMBIGUOUSLY matched component - quantity = how many times it
      appeared in model_names (a plate commonly prints several copies of
      the same part).
    - ambiguous = list[(model_name, candidates, quantity)] for any model
      name whose normalized key matches MORE THAN ONE component - this
      happens when the warehouse has several components under different
      articles/codes that share the exact same name (confirmed live
      2026-09-28). There's no correct automatic choice here - which
      article is "the" target for that name is a warehouse-stock decision,
      not something derivable from the CTB/model data - so these are
      surfaced separately for the operator to resolve instead of silently
      picking whichever component happened to come first in the warehouse
      list (the old behavior - see the picker's composition UI).
    - unmatched = the model names with no match at all, so the picker can
      show the operator what it couldn't place instead of silently
      dropping it.

    Matches against BOTH a component's `code` and `name` fields - live data
    confirmed 2026-09-25 that real STL file names correspond to `name`
    ("WW-35033 _W_R_A"), not the shorter, colon-separated `code`
    ("WW-35033W:RA") real files are never actually named after. Checking
    both keeps this working for any other product family that *does*
    happen to use code-style file names."""
    by_key = {}
    for c in components:
        # 2026-10-02: /api/warehouse also returns soft-deleted components
        # (deletedAt set - 248 of 1867 live), and PUT ctb-mappings answers
        # 404 "Component not found" for them. The WW-35029 wheel family
        # had old deleted records (code WW-35028:*) sharing names with
        # their live replacements, so every plate was flagged "ambiguous"
        # with the deleted record first in the picker - the save then
        # 404'd silently (log only) and ScaleX showed "Состав не назначен".
        if c.get("deletedAt"):
            continue
        for key_field in ("code", "name"):
            key = _normalize_composition_key(c.get(key_field) or "")
            if not key:
                continue
            group = by_key.setdefault(key, [])
            if not any(existing["id"] == c["id"] for existing in group):
                group.append(c)

    counts = {}
    ambiguous_groups = {}  # stem -> {"model_name": str, "candidates": [...], "quantity": int}
    unmatched = []
    for name in model_names:
        stem = _normalize_composition_key(os.path.splitext(name)[0])
        candidates = by_key.get(stem)
        if not candidates:
            unmatched.append(name)
        elif len(candidates) == 1:
            cid = candidates[0]["id"]
            counts[cid] = counts.get(cid, 0) + 1
        else:
            group = ambiguous_groups.setdefault(
                stem, {"model_name": name, "candidates": candidates, "quantity": 0})
            group["quantity"] += 1

    comp_by_id = {c["id"]: c for c in components}
    matched = [(comp_by_id[cid], qty) for cid, qty in counts.items()]
    ambiguous = [(g["model_name"], g["candidates"], g["quantity"]) for g in ambiguous_groups.values()]
    return matched, ambiguous, unmatched


def _composition_item_label(component):
    """'name (арт. code)' for the composition notice - shows the actual
    detected article alongside the name, since confirming *which* article
    got matched is the useful thing to glance at before sending, not just
    that something matched. Falls back to whichever of name/code exists
    when the other is missing, and avoids a redundant "X (арт. X)" when
    they're identical."""
    name = component.get("name")
    code = component.get("code")
    if name and code and name != code:
        label = "%s (арт. %s)" % (name, code)
    else:
        label = name or code or component.get("id") or "?"
    if component.get("warehouseContext") == "orders":
        label += " [склад заказов]"
    return label


def suggest_composition_matches(unmatched_names, components, cutoff=0.85):
    """Display-only "did you mean" for model names that matched no live
    warehouse component: {model_name: component label}. Never used to
    assign anything - which part gets decremented from stock must stay an
    operator decision. Live case (2026-10-02): plates named WW-35042_L_A
    while the warehouse holds WM-35042_L_A (WW vs WM) - exact matching
    rightly refuses that, but the operator should be told why."""
    import difflib
    labels = {}
    for c in components:
        if c.get("deletedAt"):
            continue
        for field in ("code", "name"):
            label = c.get(field)
            key = _normalize_composition_key(label or "")
            if key:
                labels.setdefault(key, label)
    keys = list(labels)

    def tail(key):
        return re.sub(r"^[a-z]+-?", "", key)

    by_tail = {}
    for k in keys:
        by_tail.setdefault(tail(k), []).append(k)

    out = {}
    for name in dict.fromkeys(unmatched_names):
        stem = _normalize_composition_key(os.path.splitext(name)[0])
        # Same number/suffix, different letter prefix first (WW-35042_L_A
        # vs WM-35042_L_A - the typical typo), then plain closeness. Up to
        # 3, not 1: WW-35032_L_A is just as close by edit distance but a
        # different real part, so one silent pick could mislead - show the
        # candidates and let the operator judge.
        same_tail = [k for k in by_tail.get(tail(stem), []) if k != stem] if len(tail(stem)) >= 5 else []
        close = same_tail + [k for k in difflib.get_close_matches(stem, keys, n=3, cutoff=cutoff)
                             if k not in same_tail]
        if close:
            out[name] = [labels[k] for k in close[:3]]
    return out
