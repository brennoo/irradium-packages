"""cpe-map.tsv parser, version transforms, and CPE maintenance commands (lint, coverage, verify, suggest)."""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

from . import ports

CPE_MAP_PATH = pathlib.Path(
    os.environ.get("CPE_MAP_FILE", str(ports.BUILDER_DIR / "cpe-map.tsv"))
).resolve()
NVD_CACHE_DIR = pathlib.Path(
    os.environ.get("NVD_CACHE_DIR", str(ports.ROOT_DIR / "cache" / "nvd"))
).resolve()

NVD_CPE_API_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
REPOLOGY_API_URL = "https://repology.org/api/v1/project"

NAMED_XFORMS = {"none", "-", "", "underscore-to-dot", "p-suffix-to-update"}


@dataclasses.dataclass(frozen=True)
class CpeEntry:
    pkg: str
    vendor: str
    product: str
    version_xform: str = "none"
    notes: str = ""
    line_no: int = 0

    @property
    def is_ignored(self) -> bool:
        return self.vendor == "-" and self.product == "-"

    def transform_version(self, raw_version: str) -> tuple[str, str]:
        """Return (cpe_version, cpe_update) after applying version_xform."""
        return apply_version_xform(raw_version, self.version_xform)

    def format_cpe(self, raw_version: str) -> tuple[str, str, str]:
        """Return (cpe23_string, cpe_version, cpe_update)."""
        cpe_ver, cpe_upd = self.transform_version(raw_version)
        return format_cpe23(self.vendor, self.product, cpe_ver, cpe_upd), cpe_ver, cpe_upd


def is_valid_xform(xform: str) -> bool:
    """Return True if xform is a supported named transform."""
    x = (xform or "").strip()
    if x in NAMED_XFORMS:
        return True
    if x.startswith("strip-prefix:") and len(x) > len("strip-prefix:"):
        return True
    return False


def normalize_xform(xform: str) -> str:
    """Normalize empty or '-' transform sentinel to 'none'."""
    x = (xform or "").strip()
    if x in ("", "-"):
        return "none"
    return x


def apply_version_xform(version: str, xform: str = "none") -> tuple[str, str]:
    """Transform a package version into (cpe_version, cpe_update) according to xform.

    Supported transforms:
      - 'none' / '-' / '': (version, '*')
      - 'underscore-to-dot': '1_2_3' -> ('1.2.3', '*')
      - 'p-suffix-to-update': '4.2.8p18' / '4.2.8.p18' / '4.4.3_p1' -> ('4.2.8p18', 'p18')
        (keeps normalized '<base>p<N>' in the 5th CPE version field so Grype's stock-matcher
        evaluates patch-level constraints like '< 4.2.8p9' and '<= 4.2.8' accurately, while
        also populating the 6th CPE 2.3 update field 'p18')
      - 'strip-prefix:<s>': drop leading string <s> -> (stripped, '*')
    """
    norm = normalize_xform(xform)
    if norm == "none":
        return version, "*"
    if norm == "underscore-to-dot":
        return version.replace("_", "."), "*"
    if norm == "p-suffix-to-update":
        m = re.match(r"^(.+?)[._-]?([pP][0-9]+)$", version)
        if m:
            upd = m.group(2).lower()
            return f"{m.group(1)}{upd}", upd
        return version, "*"
    if norm.startswith("strip-prefix:"):
        prefix = norm.split(":", 1)[1]
        if prefix and version.startswith(prefix):
            return version[len(prefix) :], "*"
        return version, "*"
    raise ValueError(f"Unknown version_xform: {xform!r}")


def format_cpe23(
    vendor: str,
    product: str,
    cpe_version: str,
    cpe_update: str = "*",
) -> str:
    """Build a CPE 2.3 string with cpe_version in field 5 and cpe_update in field 6."""
    ver_field = cpe_version if cpe_version else "*"
    upd_field = cpe_update if cpe_update else "*"
    return f"cpe:2.3:a:{vendor}:{product}:{ver_field}:{upd_field}:*:*:*:*:*:*"


def load_cpe_map(
    path: pathlib.Path | None = None,
) -> tuple[dict[str, list[CpeEntry]], list[str]]:
    """Parse cpe-map.tsv into (entries_by_pkg, lint_errors)."""
    map_path = path or CPE_MAP_PATH
    entries_by_pkg: dict[str, list[CpeEntry]] = {}
    errors: list[str] = []

    if not map_path.is_file():
        errors.append(f"CPE map file not found: {map_path}")
        return entries_by_pkg, errors

    seen_rows: set[tuple[str, str, str, str]] = set()
    for line_no, raw_line in enumerate(
        map_path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        cols = raw_line.split("\t")
        if len(cols) < 3 or len(cols) > 5:
            errors.append(
                f"{map_path.name}:{line_no}: expected 3 to 5 tab-separated columns, got {len(cols)}"
            )
            continue

        pkg = cols[0].strip()
        vendor = cols[1].strip()
        product = cols[2].strip()
        raw_xform = cols[3].strip() if len(cols) >= 4 else ""
        notes = cols[4].strip() if len(cols) >= 5 else ""

        if not pkg or not vendor or not product:
            errors.append(
                f"{map_path.name}:{line_no}: pkg, vendor, and product must be non-empty"
            )
            continue

        if any( re.search(r"\s", val) for val in (pkg, vendor, product) ):
            errors.append(
                f"{map_path.name}:{line_no}: whitespace not allowed in pkg/vendor/product ({pkg!r}, {vendor!r}, {product!r})"
            )
            continue

        if (vendor == "-") != (product == "-"):
            errors.append(
                f"{map_path.name}:{line_no}:for '{pkg}', vendor and product must both be '-' or both be valid CPE identifiers"
            )
            continue

        if not is_valid_xform(raw_xform):
            errors.append(
                f"{map_path.name}:{line_no}: unknown version_xform {raw_xform!r} for '{pkg}'"
            )
            continue

        norm_xform = normalize_xform(raw_xform)
        if vendor == "-" and norm_xform != "none":
            errors.append(
                f"{map_path.name}:{line_no}: ignored package '{pkg}' ('-') cannot specify version_xform {raw_xform!r}"
            )
            continue

        row_key = (pkg, vendor, product, norm_xform)
        if row_key in seen_rows:
            errors.append(
                f"{map_path.name}:{line_no}: duplicate row for {pkg} ({vendor}:{product}, xform={norm_xform})"
            )
            continue
        seen_rows.add(row_key)

        entry = CpeEntry(
            pkg=pkg,
            vendor=vendor,
            product=product,
            version_xform=norm_xform,
            notes=notes,
            line_no=line_no,
        )
        existing = entries_by_pkg.setdefault(pkg, [])
        if existing:
            if existing[0].is_ignored or entry.is_ignored:
                errors.append(
                    f"{map_path.name}:{line_no}: package '{pkg}' mixes '-' sentinel with other CPE rows"
                )
        existing.append(entry)

    return entries_by_pkg, errors


def _nvd_get_json(
    params: dict[str, str],
    cache_file: pathlib.Path,
    refresh: bool = False,
) -> tuple[dict, bool]:
    """Query the NVD CPE 2.0 API with local file caching under cache/nvd/.

    Returns (json_dict, came_from_cache).
    """
    NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if cache_file.is_file() and not refresh:
        try:
            return json.loads(cache_file.read_text(encoding="utf-8")), True
        except Exception:
            pass

    query = urllib.parse.urlencode(params)
    url = f"{NVD_CPE_API_URL}?{query}"
    headers = {
        "User-Agent": "irradium-vulntool/1.0",
        "Accept": "application/json",
    }
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            return data, False
        except Exception as exc:
            last_exc = exc
            if attempt < 2:
                time.sleep(6.0 * (attempt + 1))
    assert last_exc is not None
    raise last_exc


def _repology_get_cpes(pkg: str, refresh: bool = False) -> list[tuple[str, str]]:
    """Query Repology for known CPE vendor:product pairs for pkg."""
    NVD_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._+-]", "_", pkg)
    cache_file = NVD_CACHE_DIR / f"repology_{safe_name}.json"

    data = None
    if cache_file.is_file() and not refresh:
        try:
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except Exception:
            data = None

    if data is None:
        url = f"{REPOLOGY_API_URL}/{urllib.parse.quote(pkg)}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "irradium-vulntool/1.0 (+https://github.com/brennoo/irradium-packages)",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            cache_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            return []

    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            v = item.get("cpe_vendor")
            p = item.get("cpe_product")
            if v and p and (v, p) not in seen:
                seen.add((v, p))
                pairs.append((v, p))
    return pairs


def _extract_url_tokens(url: str) -> set[str]:
    """Extract lowercase tokens from a Pkgfile # URL: (domain, github org, repo)."""
    tokens: set[str] = set()
    if not url:
        return tokens
    try:
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        for part in host.split("."):
            if part not in ("www", "org", "com", "net", "io", "dev", "nu", "uk", "de", "se", "br", "git", "downloads", "ftp", "dl"):
                tokens.add(part)
        for seg in parsed.path.strip("/").split("/"):
            clean = re.sub(r"\.git$", "", seg.lower())
            if clean and clean not in ("releases", "download", "archive", "tags", "pub", "software", "projects", "files"):
                tokens.add(clean)
    except Exception:
        pass
    return tokens


def cmd_lint(args: argparse.Namespace) -> int:
    """Offline structural check of cpe-map.tsv + coverage verification."""
    map_path = pathlib.Path(args.map_file).resolve() if getattr(args, "map_file", None) else CPE_MAP_PATH
    entries_by_pkg, lint_errors = load_cpe_map(map_path)

    resolved_ports, missing_ports = ports.resolve_ports(
        include_all=getattr(args, "all", False),
        use_mirror=not getattr(args, "offline", False),
    )

    if missing_ports:
        for m in missing_ports:
            lint_errors.append(f"Package '{m}' not found in any configured port tree")

    unmapped = [p.name for p in resolved_ports if p.name not in entries_by_pkg]

    total_rows = sum(len(v) for v in entries_by_pkg.values())
    if lint_errors:
        for err in lint_errors:
            print(f"ERROR: {err}", file=sys.stderr)
    if unmapped:
        print(
            f"ERROR: {len(unmapped)} resolved package(s) missing from {map_path.name}: "
            f"{', '.join(unmapped)}",
            file=sys.stderr,
        )

    if lint_errors or unmapped:
        return 1

    scope = "build.txt + upstream.txt + dependencies" if getattr(args, "all", False) else "build.txt + upstream.txt"
    print(
        f"==> cpe lint OK: {total_rows} row(s) covering {len(entries_by_pkg)} mapped package(s); "
        f"all {len(resolved_ports)} package(s) in {scope} are mapped."
    )
    return 0


def cmd_coverage(args: argparse.Namespace) -> int:
    """Report CPE map coverage across build.txt, upstream.txt, and optionally dependencies."""
    map_path = pathlib.Path(args.map_file).resolve() if getattr(args, "map_file", None) else CPE_MAP_PATH
    entries_by_pkg, lint_errors = load_cpe_map(map_path)
    if lint_errors:
        for err in lint_errors:
            print(f"WARN: {err}", file=sys.stderr)

    resolved_ports, missing_ports = ports.resolve_ports(
        include_all=getattr(args, "all", False),
        use_mirror=not getattr(args, "offline", False),
    )

    mapped_cpe: list[ports.PortInfo] = []
    mapped_ignored: list[ports.PortInfo] = []
    unmapped: list[ports.PortInfo] = []

    for p in resolved_ports:
        entries = entries_by_pkg.get(p.name)
        if not entries:
            unmapped.append(p)
        elif entries[0].is_ignored:
            mapped_ignored.append(p)
        else:
            mapped_cpe.append(p)

    total = len(resolved_ports)
    covered = len(mapped_cpe) + len(mapped_ignored)
    pct = (covered * 100.0 / total) if total else 100.0
    print(
        f"==> CPE Coverage ({'all incl. dependencies' if getattr(args, 'all', False) else 'top-level lists'}): "
        f"{covered}/{total} ({pct:.1f}%) — "
        f"{len(mapped_cpe)} NVD CPE, {len(mapped_ignored)} no-CPE ('-'), {len(unmapped)} unmapped"
    )

    if missing_ports:
        print(f"ERROR: Missing from port trees: {', '.join(missing_ports)}", file=sys.stderr)

    if unmapped:
        print("\nUnmapped packages:")
        for p in unmapped:
            print(f"  {p.name}\t({p.collection}, {p.version_release}, {p.source_kind})\t{p.url}")
        return 1

    if missing_ports:
        return 1
    return 0


def _changed_pkgs_in_diff(diff_ref: str, map_path: pathlib.Path) -> set[str]:
    """Return package names whose rows were added/modified in cpe-map.tsv relative to diff_ref."""
    rel_map = map_path.relative_to(ports.ROOT_DIR)
    res = subprocess.run(
        ["git", "-C", str(ports.ROOT_DIR), "diff", "-U0", diff_ref, "--", str(rel_map)],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        return set()
    changed: set[str] = set()
    for line in res.stdout.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:].strip()
            if content and not content.startswith("#"):
                pkg = content.split("\t", 1)[0].strip()
                if pkg:
                    changed.add(pkg)
    return changed


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify mapped vendor:product pairs against the live/cached NVD CPE dictionary."""
    map_path = pathlib.Path(args.map_file).resolve() if getattr(args, "map_file", None) else CPE_MAP_PATH
    entries_by_pkg, lint_errors = load_cpe_map(map_path)
    if lint_errors:
        for err in lint_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    target_pkgs: set[str]
    if getattr(args, "packages", None):
        target_pkgs = set(args.packages)
    elif getattr(args, "diff", None):
        target_pkgs = _changed_pkgs_in_diff(args.diff, map_path)
        if not target_pkgs:
            print(f"==> No added/changed rows in {map_path.name} relative to {args.diff}; nothing to verify.")
            return 0
    else:
        target_pkgs = set(entries_by_pkg.keys())

    pairs_to_check: list[tuple[str, str, list[str]]] = []
    by_pair: dict[tuple[str, str], list[str]] = {}
    for pkg in sorted(target_pkgs):
        for entry in entries_by_pkg.get(pkg, []):
            if entry.is_ignored:
                continue
            by_pair.setdefault((entry.vendor, entry.product), []).append(pkg)

    for (vendor, product), pkgs in sorted(by_pair.items()):
        pairs_to_check.append((vendor, product, pkgs))

    if not pairs_to_check:
        print("==> No non-ignored CPE entries selected for verification.")
        return 0

    has_api_key = bool(os.environ.get("NVD_API_KEY", "").strip())
    delay = 0.65 if has_api_key else 6.0

    failures = 0
    last_net_call = 0.0
    for vendor, product, pkgs in pairs_to_check:
        safe_vp = re.sub(r"[^a-zA-Z0-9._+-]", "_", f"{vendor}__{product}")
        cache_file = NVD_CACHE_DIR / f"verify_{safe_vp}.json"
        if not cache_file.is_file() or getattr(args, "refresh", False):
            elapsed = time.time() - last_net_call
            if last_net_call > 0 and elapsed < delay:
                time.sleep(delay - elapsed)

        try:
            data, from_cache = _nvd_get_json(
                {
                    "cpeMatchString": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
                    "resultsPerPage": "20",
                },
                cache_file=cache_file,
                refresh=getattr(args, "refresh", False),
            )
            if not from_cache:
                last_net_call = time.time()
        except Exception as exc:
            last_net_call = time.time()
            print(
                f"ERROR: NVD API request failed for {vendor}:{product} ({', '.join(pkgs)}): {exc}",
                file=sys.stderr,
            )
            failures += 1
            continue

        total_results = data.get("totalResults", 0)
        products = data.get("products", [])
        active_count = sum(
            1
            for item in products
            if not item.get("cpe", {}).get("deprecated", False)
        )
        if total_results == 0:
            print(
                f"FAIL: {vendor}:{product} (used by {', '.join(pkgs)}) not found in NVD CPE dictionary",
                file=sys.stderr,
            )
            failures += 1
        elif active_count == 0 and products:
            print(
                f"FAIL: {vendor}:{product} (used by {', '.join(pkgs)}) has only deprecated CPE entries in NVD",
                file=sys.stderr,
            )
            failures += 1
        else:
            src_tag = "cached" if from_cache else "live"
            print(
                f"  OK: {vendor}:{product}\t({total_results} NVD CPEs, {src_tag})\t<- {', '.join(pkgs)}"
            )

    if failures:
        print(f"==> cpe verify FAILED: {failures}/{len(pairs_to_check)} vendor:product pair(s) invalid", file=sys.stderr)
        return 1

    print(f"==> cpe verify OK: {len(pairs_to_check)} vendor:product pair(s) verified.")
    return 0


def _suggest_xform_for_version(version: str) -> str:
    if re.match(r"^.+?[._-]?[pP][0-9]+$", version):
        return "p-suffix-to-update"
    if "_" in version:
        return "underscore-to-dot"
    if version.startswith("v") and len(version) > 1 and version[1].isdigit():
        return "strip-prefix:v"
    return ""


def cmd_suggest(args: argparse.Namespace) -> int:
    """Query NVD CPE API (and Repology) to suggest cpe-map.tsv rows for packages."""
    port_index = ports.build_port_index()
    has_api_key = bool(os.environ.get("NVD_API_KEY", "").strip())
    delay = 0.65 if has_api_key else 6.0
    last_net_call = 0.0

    rc = 0
    for pkg in args.packages:
        entry = port_index.get(pkg)
        url = entry.url if entry else ""
        desc = entry.description if entry else ""
        ver = ""
        if entry:
            ver, _ = ports.source_pkgfile(entry.port_dir)
        url_tokens = _extract_url_tokens(url)

        print(f"==> {pkg} (version={ver or '?'}, url={url or 'n/a'})")
        if desc:
            print(f"    Description: {desc}")

        repology_pairs = _repology_get_cpes(pkg, refresh=getattr(args, "refresh", False))
        repology_set = set(repology_pairs)

        safe_pkg = re.sub(r"[^a-zA-Z0-9._+-]", "_", pkg)
        cache_file = NVD_CACHE_DIR / f"suggest_{safe_pkg}.json"
        if not cache_file.is_file() or getattr(args, "refresh", False):
            elapsed = time.time() - last_net_call
            if last_net_call > 0 and elapsed < delay:
                time.sleep(delay - elapsed)

        candidates: dict[tuple[str, str], int] = {}
        try:
            data, from_cache = _nvd_get_json(
                {"keywordSearch": pkg, "resultsPerPage": "100"},
                cache_file=cache_file,
                refresh=getattr(args, "refresh", False),
            )
            if not from_cache:
                last_net_call = time.time()
            for item in data.get("products", []):
                cpe_obj = item.get("cpe", {})
                if cpe_obj.get("deprecated", False):
                    continue
                cpe_name = cpe_obj.get("cpeName", "")
                parts = cpe_name.split(":")
                if len(parts) >= 5 and parts[2] == "a":
                    v, p = parts[3], parts[4]
                    candidates[(v, p)] = candidates.get((v, p), 0) + 1
        except Exception as exc:
            print(f"    WARN: NVD query failed for {pkg}: {exc}", file=sys.stderr)

        for vp in repology_pairs:
            candidates.setdefault(vp, 1)

        if not candidates:
            print(f"    No NVD CPE candidates found. Suggested sentinel row:")
            print(f"    {pkg}\t-\t-\t\tno NVD product")
            continue

        norm_pkg = pkg.lower().replace("-", "_")

        def _score(item: tuple[tuple[str, str], int]) -> tuple[int, int, str, str]:
            (v, p), count = item
            s = 0
            vl = v.lower()
            pl = p.lower()
            if pl == pkg.lower() or pl == norm_pkg:
                s += 50
            elif pkg.lower() in pl or norm_pkg in pl:
                s += 20
            if (v, p) in repology_set:
                s += 40
            if vl in url_tokens or vl.replace("_project", "") in url_tokens:
                s += 35
            if pl in url_tokens:
                s += 25
            if vl == f"{norm_pkg}_project":
                s += 15
            s += min(count, 20)
            return (s, count, v, p)

        ranked = sorted(candidates.items(), key=_score, reverse=True)
        suggested_xform = _suggest_xform_for_version(ver)

        print("    Candidates (ranked):")
        for (v, p), count in ranked[:5]:
            score_val = _score(((v, p), count))[0]
            rep_tag = " [repology]" if (v, p) in repology_set else ""
            print(f"      {v}:{p}\t(score={score_val}, nvd_entries={count}{rep_tag})")

        best_v, best_p = ranked[0][0]
        print("    Suggested cpe-map.tsv row:")
        if suggested_xform:
            print(f"    {pkg}\t{best_v}\t{best_p}\t{suggested_xform}")
        else:
            print(f"    {pkg}\t{best_v}\t{best_p}")

    return rc
