"""OpenVEX loading, validation, auto-generation from port CVE patches, and CLI commands."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import pathlib
import re
import sys

from . import cpe, ports

VEX_DIR = pathlib.Path(
    os.environ.get("VEX_DIR", str(ports.BUILDER_DIR / "vex"))
).resolve()

VALID_STATUSES = {"not_affected", "fixed"}

VALID_JUSTIFICATIONS = {
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
}

CVE_ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.I)
CVE_HEADER_LINE_RE = re.compile(r"^(?:#\s*|\*\s*|--\s*|\s*)CVE(?:s|-ID)?\s*:\s*(.+)$", re.I)


@dataclasses.dataclass(frozen=True)
class VexStatement:
    pkg: str
    version: str
    cve: str
    status: str  # "not_affected" | "fixed"
    justification: str = ""
    note: str = ""
    source: str = "manual"
    timestamp: str = ""

    def matches_port_version(self, port: ports.PortInfo) -> bool:
        """Return True if this statement is bound to the port's current exact version (or '*' for all versions)."""
        if self.version == "*":
            return True
        return self.version in (
            port.version,
            port.version_release,
            port.pkgfile_version,
            port.pkgfile_version_release,
        )


def urllib_parse_unquote(val: str) -> str:
    import urllib.parse

    return urllib.parse.unquote(val)


def _parse_single_statement_obj(
    obj: dict,
    source_label: str,
    default_timestamp: str = "",
) -> tuple[list[VexStatement], list[str]]:
    """Parse either a compact statement dict or an OpenVEX statement dict."""
    stmts: list[VexStatement] = []
    errors: list[str] = []

    if "pkg" in obj or "cve" in obj:
        pkg = str(obj.get("pkg", "")).strip()
        version = str(obj.get("version", "")).strip()
        cve_id = str(obj.get("cve", "")).strip().upper()
        status = str(obj.get("status", "")).strip()
        justification = str(obj.get("justification", "")).strip()
        note = str(obj.get("note", obj.get("impact_statement", obj.get("action_statement", "")))).strip()
        ts = str(obj.get("timestamp", default_timestamp)).strip()

        if not pkg or not version or not cve_id or not status:
            errors.append(f"{source_label}: statement missing required field(s) (pkg, version, cve, status)")
            return stmts, errors
        if not CVE_ID_RE.fullmatch(cve_id):
            errors.append(f"{source_label}: invalid CVE identifier {cve_id!r} for {pkg}")
            return stmts, errors
        if status not in VALID_STATUSES:
            errors.append(
                f"{source_label}: invalid status {status!r} for {pkg} {cve_id} (expected one of {sorted(VALID_STATUSES)})"
            )
            return stmts, errors
        if version == "*" and status != "not_affected":
            errors.append(
                f"{source_label}: {pkg} {cve_id} wildcard version '*' is only valid with status 'not_affected'"
            )
            return stmts, errors
        if status == "not_affected":
            if justification not in VALID_JUSTIFICATIONS:
                errors.append(
                    f"{source_label}: {pkg} {cve_id} (not_affected) requires a valid OpenVEX justification "
                    f"({', '.join(sorted(VALID_JUSTIFICATIONS))}), got {justification!r}"
                )
                return stmts, errors
            if not note:
                errors.append(
                    f"{source_label}: {pkg} {cve_id} (not_affected) requires a non-empty free-text 'note'"
                )
                return stmts, errors

        stmts.append(
            VexStatement(
                pkg=pkg,
                version=version,
                cve=cve_id,
                status=status,
                justification=justification,
                note=note,
                source=source_label,
                timestamp=ts,
            )
        )
        return stmts, errors

    # Full OpenVEX statement format
    vuln_obj = obj.get("vulnerability", {})
    cve_id = (
        vuln_obj.get("name", "") if isinstance(vuln_obj, dict) else str(vuln_obj)
    ).strip().upper()
    status = str(obj.get("status", "")).strip()
    justification = str(obj.get("justification", "")).strip()
    note = str(
        obj.get("note", obj.get("impact_statement", obj.get("action_statement", "")))
    ).strip()
    ts = str(obj.get("timestamp", default_timestamp)).strip()
    products = obj.get("products", [])

    if not cve_id or not CVE_ID_RE.fullmatch(cve_id):
        errors.append(f"{source_label}: invalid or missing vulnerability.name {cve_id!r}")
        return stmts, errors
    if status not in VALID_STATUSES:
        errors.append(f"{source_label}: invalid status {status!r} for {cve_id}")
        return stmts, errors
    if status == "not_affected":
        if justification not in VALID_JUSTIFICATIONS:
            errors.append(
                f"{source_label}: {cve_id} (not_affected) requires valid OpenVEX justification, got {justification!r}"
            )
            return stmts, errors
        if not note:
            errors.append(
                f"{source_label}: {cve_id} (not_affected) requires non-empty impact_statement/note"
            )
            return stmts, errors

    if not isinstance(products, list) or not products:
        errors.append(f"{source_label}: {cve_id} has no products list")
        return stmts, errors

    for prod in products:
        pid = (prod.get("@id", "") if isinstance(prod, dict) else str(prod)).strip()
        m = re.match(r"^pkg:[^/]+/([^@]+)(?:@(.+))?$", pid)
        if not m:
            errors.append(
                f"{source_label}: product @id {pid!r} must be a PURL 'pkg:generic/<pkg>@<version>' (or 'pkg:generic/<pkg>' for not_affected)"
            )
            continue
        pkg = urllib_parse_unquote(m.group(1))
        version = urllib_parse_unquote(m.group(2)) if m.group(2) else "*"
        if version == "*" and status != "not_affected":
            errors.append(
                f"{source_label}: product @id {pid!r} without '@<version>' is only valid with status 'not_affected'"
            )
            continue
        stmts.append(
            VexStatement(
                pkg=pkg,
                version=version,
                cve=cve_id,
                status=status,
                justification=justification,
                note=note,
                source=source_label,
                timestamp=ts,
            )
        )

    return stmts, errors


def load_vex_dir(
    vex_dir: pathlib.Path | None = None,
) -> tuple[list[VexStatement], list[str]]:
    """Load and validate all hand-written VEX JSON files under builder/vex/."""
    vdir = vex_dir or VEX_DIR
    statements: list[VexStatement] = []
    errors: list[str] = []

    if not vdir.is_dir():
        return statements, errors

    for json_file in sorted(vdir.glob("*.json")):
        rel_label = f"vex/{json_file.name}"
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"{rel_label}: invalid JSON ({exc})")
            continue

        if isinstance(data, list):
            for idx, item in enumerate(data):
                if not isinstance(item, dict):
                    errors.append(f"{rel_label}[{idx}]: expected object")
                    continue
                s, e = _parse_single_statement_obj(item, f"{rel_label}[{idx}]")
                statements.extend(s)
                errors.extend(e)
        elif isinstance(data, dict):
            doc_ts = str(data.get("timestamp", "")).strip()
            if "statements" in data and isinstance(data["statements"], list):
                for idx, item in enumerate(data["statements"]):
                    if not isinstance(item, dict):
                        errors.append(f"{rel_label}#statements[{idx}]: expected object")
                        continue
                    s, e = _parse_single_statement_obj(
                        item, f"{rel_label}#statements[{idx}]", default_timestamp=doc_ts
                    )
                    statements.extend(s)
                    errors.extend(e)
            else:
                s, e = _parse_single_statement_obj(data, rel_label, default_timestamp=doc_ts)
                statements.extend(s)
                errors.extend(e)
        else:
            errors.append(f"{rel_label}: top-level JSON value must be an object or array")

    return statements, errors


def discover_port_cve_patches(port_dir: pathlib.Path) -> dict[str, list[str]]:
    """Scan a port directory for CVE-YYYY-NNNNN*.patch files or patches with a 'CVE:' header line.

    Returns dict mapping uppercase CVE ID -> list of patch filenames in port_dir.
    """
    found: dict[str, list[str]] = {}
    if not port_dir.is_dir():
        return found

    for entry in sorted(port_dir.iterdir(), key=lambda p: p.name):
        if not entry.is_file():
            continue
        is_patch = entry.name.endswith((".patch", ".diff")) or CVE_ID_RE.search(entry.name)
        if not is_patch:
            continue

        cves_in_file: set[str] = set()
        # 1. Check filename for CVE-YYYY-NNNNN*
        for m in CVE_ID_RE.finditer(entry.name):
            cves_in_file.add(m.group(1).upper())

        # 2. Check patch header lines for `CVE: CVE-YYYY-NNNNN`
        if entry.name.endswith((".patch", ".diff")):
            try:
                with entry.open("r", encoding="utf-8", errors="replace") as f:
                    for _ in range(80):
                        line = f.readline()
                        if not line:
                            break
                        if line.startswith(("diff ", "--- ", "+++ ", "@@ ")):
                            break
                        hm = CVE_HEADER_LINE_RE.match(line.strip())
                        if hm:
                            for cm in CVE_ID_RE.finditer(hm.group(1)):
                                cves_in_file.add(cm.group(1).upper())
            except Exception:
                pass

        for cve_id in sorted(cves_in_file):
            found.setdefault(cve_id, []).append(entry.name)

    return found


def discover_auto_vex_for_ports(
    resolved_ports: list[ports.PortInfo],
) -> list[VexStatement]:
    """Generate automatic 'fixed' VEX statements from CVE patches in resolved port directories."""
    auto_stmts: list[VexStatement] = []
    for port in resolved_ports:
        cve_map = discover_port_cve_patches(port.port_dir)
        for cve_id, patch_names in sorted(cve_map.items()):
            patches_str = ", ".join(patch_names)
            auto_stmts.append(
                VexStatement(
                    pkg=port.name,
                    version=port.version,
                    cve=cve_id,
                    status="fixed",
                    justification="",
                    note=f"Patched in {port.collection}/{port.name} ({patches_str})",
                    source=f"auto:{port.collection}/{port.name}/{patch_names[0]}",
                )
            )
    return auto_stmts


def collect_active_vex(
    resolved_ports: list[ports.PortInfo],
    vex_dir: pathlib.Path | None = None,
) -> tuple[dict[tuple[str, str], VexStatement], list[VexStatement], list[str]]:
    """Collect active VEX statements for resolved_ports.

    Returns:
      - active_by_pkg_cve: dict[(pkg_name, cve_id)] -> VexStatement
      - stale_manual: list of hand-written VexStatements whose version does not match current port version
      - errors: validation errors from builder/vex/
    """
    manual_stmts, errors = load_vex_dir(vex_dir=vex_dir)
    auto_stmts = discover_auto_vex_for_ports(resolved_ports)
    port_by_name = {p.name: p for p in resolved_ports}

    active: dict[tuple[str, str], VexStatement] = {}
    stale: list[VexStatement] = []

    for stmt in auto_stmts:
        active[(stmt.pkg, stmt.cve)] = stmt

    for stmt in manual_stmts:
        port = port_by_name.get(stmt.pkg)
        if port is None:
            # Check if port exists in port tree at all to see if version is still current
            found = ports.find_port(stmt.pkg)
            if found:
                col, cat, pdir = found
                ver, rel = ports.source_pkgfile(pdir)
                dummy = ports.PortInfo(
                    name=stmt.pkg,
                    version=ver,
                    release=rel,
                    pkgfile_version=ver,
                    pkgfile_release=rel,
                    collection=col,
                    category=cat,
                    port_dir=pdir,
                )
                if not stmt.matches_port_version(dummy):
                    stale.append(stmt)
            continue

        if stmt.matches_port_version(port):
            active[(stmt.pkg, stmt.cve)] = stmt
        else:
            stale.append(stmt)

    return active, stale, errors


def build_openvex_document(
    active_statements: list[VexStatement],
    resolved_ports: list[ports.PortInfo],
    cpe_map: dict[str, list[cpe.CpeEntry]] | None = None,
) -> dict:
    """Build a standard OpenVEX v0.2.0 JSON document consumable by `grype --vex`."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    port_by_name = {p.name: p for p in resolved_ports}

    ov_statements: list[dict] = []
    for stmt in active_statements:
        port = port_by_name.get(stmt.pkg)
        versions_for_purl: set[str] = set()
        if stmt.version and stmt.version != "*":
            versions_for_purl.add(stmt.version)
        if port:
            versions_for_purl.add(port.version)
            if cpe_map and port.name in cpe_map:
                for entry in cpe_map[port.name]:
                    if not entry.is_ignored:
                        cpe_ver, _ = entry.transform_version(port.version)
                        versions_for_purl.add(cpe_ver)

        products = [
            {"@id": f"pkg:generic/{stmt.pkg}@{ver}"}
            for ver in sorted(versions_for_purl)
            if ver
        ]
        if not products:
            products = [{"@id": f"pkg:generic/{stmt.pkg}"}]
        ov_stmt: dict = {
            "vulnerability": {"name": stmt.cve},
            "timestamp": stmt.timestamp or now_iso,
            "products": products,
            "status": stmt.status,
        }
        if stmt.status == "not_affected":
            ov_stmt["justification"] = stmt.justification
            ov_stmt["impact_statement"] = stmt.note
        elif stmt.note:
            ov_stmt["action_statement"] = stmt.note
        ov_statements.append(ov_stmt)

    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://pkg.irradium.com.br/vex/irradium-3.8",
        "author": "irradium-packages",
        "timestamp": now_iso,
        "version": 1,
        "statements": ov_statements,
    }


def cmd_lint(args: argparse.Namespace) -> int:
    """Validate hand-written VEX files in builder/vex/ and report stale statements."""
    vdir = pathlib.Path(args.vex_dir).resolve() if getattr(args, "vex_dir", None) else VEX_DIR
    resolved_ports, _ = ports.resolve_ports(include_all=True, use_mirror=False)
    active, stale, errors = collect_active_vex(resolved_ports, vex_dir=vdir)

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    if stale:
        for s in stale:
            print(
                f"WARN: Stale VEX statement for {s.pkg}@{s.version} ({s.cve} in {s.source}) — "
                f"version bumped, statement is inactive until re-triaged",
                file=sys.stderr,
            )

    manual_stmts, _ = load_vex_dir(vex_dir=vdir)
    auto_stmts = discover_auto_vex_for_ports(resolved_ports)
    print(
        f"==> vex lint OK: {len(manual_stmts)} manual statement(s), "
        f"{len(auto_stmts)} auto-generated from patches, {len(stale)} stale."
    )
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List active and stale VEX statements (both manual and auto-generated from CVE patches)."""
    vdir = pathlib.Path(args.vex_dir).resolve() if getattr(args, "vex_dir", None) else VEX_DIR
    resolved_ports, _ = ports.resolve_ports(include_all=True, use_mirror=False)
    active, stale, errors = collect_active_vex(resolved_ports, vex_dir=vdir)

    if errors:
        for err in errors:
            print(f"ERROR: {err}", file=sys.stderr)
        return 1

    if not active and not stale:
        print("==> No VEX statements found (manual in builder/vex/ or auto-generated from CVE patches).")
        return 0

    if active:
        print(f"Active VEX statements ({len(active)}):")
        for (_pkg, _cve), s in sorted(active.items()):
            just = f" [{s.justification}]" if s.justification else ""
            print(f"  {s.pkg}@{s.version}\t{s.cve}\t{s.status}{just}\t({s.source}) — {s.note}")

    if stale and not getattr(args, "active_only", False):
        print(f"\nStale (inactive due to version bump) VEX statements ({len(stale)}):")
        for s in stale:
            print(f"  {s.pkg}@{s.version}\t{s.cve}\t{s.status}\t({s.source}) — {s.note}")

    return 0


def cmd_add(args: argparse.Namespace) -> int:
    """Add or update a hand-written VEX statement in builder/vex/<pkg>.json."""
    vdir = pathlib.Path(args.vex_dir).resolve() if getattr(args, "vex_dir", None) else VEX_DIR
    pkg = args.pkg.strip()
    cve_id = args.cve.strip().upper()
    status = args.status.strip()
    justification = (args.justification or "").strip()
    note = (args.note or "").strip()

    if not CVE_ID_RE.fullmatch(cve_id):
        print(f"ERROR: Invalid CVE ID: {cve_id!r}", file=sys.stderr)
        return 1

    if status not in VALID_STATUSES:
        print(f"ERROR: Status must be one of {sorted(VALID_STATUSES)}", file=sys.stderr)
        return 1

    if status == "not_affected":
        if justification not in VALID_JUSTIFICATIONS:
            print(
                f"ERROR: --status not_affected requires --justification in {sorted(VALID_JUSTIFICATIONS)}",
                file=sys.stderr,
            )
            return 1
        if not note:
            print("ERROR: --status not_affected requires a non-empty --note", file=sys.stderr)
            return 1

    version = "*" if getattr(args, "all_versions", False) else (args.version or "").strip()
    if version == "*" and status != "not_affected":
        print("ERROR: Wildcard version '*' (--all-versions) is only valid with --status not_affected", file=sys.stderr)
        return 1
    if not version:
        resolved, missing = ports.resolve_ports(targets=[pkg], use_mirror=False)
        if missing or not resolved:
            print(f"ERROR: Could not resolve package '{pkg}' in port trees", file=sys.stderr)
            return 1
        version = resolved[0].version

    vdir.mkdir(parents=True, exist_ok=True)
    target_file = vdir / f"{pkg}.json"
    existing_list: list[dict] = []
    if target_file.is_file():
        try:
            loaded = json.loads(target_file.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                existing_list = loaded
            elif isinstance(loaded, dict):
                existing_list = loaded.get("statements", [loaded])
        except Exception:
            existing_list = []

    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_entry = {
        "pkg": pkg,
        "version": version,
        "cve": cve_id,
        "status": status,
        "justification": justification,
        "note": note,
        "timestamp": now_iso,
    }

    updated = False
    for idx, item in enumerate(existing_list):
        if (
            isinstance(item, dict)
            and item.get("pkg") == pkg
            and str(item.get("cve", "")).upper() == cve_id
            and (version == "*" or item.get("version") in (version, "*"))
        ):
            existing_list[idx] = new_entry
            updated = True
            break
    if not updated:
        existing_list.append(new_entry)

    target_file.write_text(json.dumps(existing_list, indent=2) + "\n", encoding="utf-8")
    print(f"==> Wrote VEX statement for {pkg}@{version} {cve_id} ({status}) to {target_file}")
    return 0
