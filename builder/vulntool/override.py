"""Override authoring and lifecycle management: fork, patch, bump, refresh, retire, status."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.request

from pkgtool import signify

from . import ports, scan, versions, vex

PATCH_LOOP_SNIPPET = 'for p in $SRC/CVE-*.patch; do patch -p1 -i "$p"; done'


@dataclasses.dataclass
class OverrideMeta:
    origin: str
    origin_commit: str
    origin_version: str
    reason: str = ""
    cves: list[str] = dataclasses.field(default_factory=list)
    retire_when: str = "upstream_has_cve_patch"
    was_prebuilt: bool = False
    created: str = ""

    @classmethod
    def load(cls, path: pathlib.Path) -> OverrideMeta:
        kv: dict[str, str] = {}
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
        cves_raw = kv.get("cves", "")
        cves_list = [c.strip().upper() for c in re.split(r"[, \t]+", cves_raw) if c.strip()]
        return cls(
            origin=kv.get("origin", ""),
            origin_commit=kv.get("origin_commit", ""),
            origin_version=kv.get("origin_version", ""),
            reason=kv.get("reason", ""),
            cves=cves_list,
            retire_when=kv.get("retire_when", "upstream_has_cve_patch"),
            was_prebuilt=kv.get("was_prebuilt", "no").lower() in ("yes", "true", "1"),
            created=kv.get("created", ""),
        )

    def save(self, path: pathlib.Path) -> None:
        lines = [
            f"origin={self.origin}",
            f"origin_commit={self.origin_commit}",
            f"origin_version={self.origin_version}",
            f"reason={self.reason}",
            f"cves={','.join(self.cves)}",
            f"retire_when={self.retire_when}",
            f"was_prebuilt={'yes' if self.was_prebuilt else 'no'}",
            f"created={self.created}",
        ]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _sync_custom_port_repo_and_sig(port_dir: pathlib.Path) -> None:
    """Sign port .signature* (when pkg-get.sec and source hashes are available) and update collection REPO."""
    sec_path = ports.ROOT_DIR / "keys" / "pkg-get.sec"
    cache_root = ports.ROOT_DIR / "cache"
    cache_source_dirs = [
        d / "sources"
        for d in sorted(cache_root.iterdir())
        if d.is_dir() and (d / "sources").is_dir()
    ] if cache_root.is_dir() else []

    cat = port_dir.parent.name.split("-")[-1]
    upstream_cands = [
        ports.PORTS_ROOT / "irradium" / f"irradium-{cat}" / port_dir.name,
        ports.PORTS_ROOT / f"crux-{cat}" / port_dir.name,
    ]
    if sec_path.is_file():
        signify.sign_port_signatures(
            port_dir,
            sec_path=sec_path,
            cache_source_dirs=cache_source_dirs,
            upstream_port_dirs=upstream_cands,
        )
    signify.update_collection_repo(port_dir.parent, ensure_ignore_file=True)


def _find_custom_override_dir(pkg: str, ports_root: pathlib.Path | None = None) -> pathlib.Path | None:
    root = ports_root or ports.PORTS_ROOT
    for cat in ports.CATEGORIES:
        cand = root / "custom" / f"custom-{cat}" / pkg
        if (cand / "Pkgfile").is_file() and (cand / ".override").is_file():
            return cand
    return None


def _resolve_origin_port_dir(origin: str, pkg: str, ports_root: pathlib.Path | None = None) -> pathlib.Path | None:
    root = ports_root or ports.PORTS_ROOT
    if origin:
        for cand in (root / origin, root / "irradium" / origin):
            if (cand / "Pkgfile").is_file():
                return cand
    found = ports.find_port(pkg, ports_root=root, include_custom=False)
    if found:
        return found[2]
    return None


def _git_head_sha(directory: pathlib.Path) -> str:
    res = subprocess.run(
        ["git", "-C", str(directory), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return res.stdout.strip() if res.returncode == 0 else "unknown"


def _remove_pkg_from_file(file_path: pathlib.Path, pkg: str) -> bool:
    if not file_path.is_file():
        return False
    lines = file_path.read_text(encoding="utf-8").splitlines()
    new_lines: list[str] = []
    removed = False
    for line in lines:
        code = line.split("#", 1)[0].strip()
        if code == pkg:
            removed = True
            continue
        new_lines.append(line)
    if removed:
        file_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    return removed


def _add_pkg_to_file(file_path: pathlib.Path, pkg: str) -> bool:
    existing = ports.read_package_list(file_path)
    if pkg in existing:
        return False
    content = file_path.read_text(encoding="utf-8") if file_path.is_file() else ""
    if content and not content.endswith("\n"):
        content += "\n"
    content += f"{pkg}\n"
    file_path.write_text(content, encoding="utf-8")
    return True


def cmd_fork(args: argparse.Namespace) -> int:
    """Fork an upstream port into ports/custom/custom-<cat>/<pkg> with .override metadata."""
    pkg = args.pkg.strip()
    existing_override = _find_custom_override_dir(pkg)
    if existing_override and not getattr(args, "force", False):
        print(
            f"ERROR: Override already exists for '{pkg}' at {existing_override} (use --force to overwrite)",
            file=sys.stderr,
        )
        return 1

    upstream = ports.find_port(pkg, include_custom=False)
    if upstream is None:
        print(f"ERROR: Package '{pkg}' not found in any upstream (irradium/crux) port tree", file=sys.stderr)
        return 1

    origin_collection, category, origin_dir = upstream
    dest_dir = ports.PORTS_ROOT / "custom" / f"custom-{category}" / pkg

    if dest_dir.exists():
        if not (dest_dir / ".override").is_file() and not getattr(args, "force", False):
            print(
                f"ERROR: {dest_dir} is an original custom port (no .override); refusing to overwrite",
                file=sys.stderr,
            )
            return 1
        shutil.rmtree(dest_dir)

    dest_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(origin_dir, dest_dir)

    # Drop inherited .signature* (signed with upstream key; invalid once edited)
    for sig_file in dest_dir.glob(".signature*"):
        sig_file.unlink()

    ver, rel = ports.source_pkgfile(origin_dir)
    origin_commit = _git_head_sha(origin_dir)

    cves: list[str] = []
    if getattr(args, "cve", None):
        for raw_cve in args.cve:
            for c in re.split(r"[, \t]+", raw_cve):
                if c.strip():
                    cves.append(c.strip().upper())

    reason = (getattr(args, "reason", None) or "").strip()
    if not reason and cves:
        reason = ",".join(cves)

    retire_when = (getattr(args, "retire_when", None) or "").strip()
    if not retire_when:
        retire_when = "upstream_has_cve_patch"

    # Check if package is in packages/upstream.txt; always ensure it is in packages/build.txt
    was_prebuilt = _remove_pkg_from_file(ports.UPSTREAM_TXT, pkg)
    _add_pkg_to_file(ports.BUILD_TXT, pkg)
    if was_prebuilt:
        print(f"==> Moved '{pkg}' from packages/upstream.txt to packages/build.txt (was_prebuilt=yes)")
    else:
        print(f"==> Added '{pkg}' to packages/build.txt (was_prebuilt=no)")

    today = datetime.date.today().isoformat()
    meta = OverrideMeta(
        origin=f"{origin_collection}/{pkg}",
        origin_commit=origin_commit,
        origin_version=f"{ver}-{rel}",
        reason=reason,
        cves=cves,
        retire_when=retire_when,
        was_prebuilt=was_prebuilt,
        created=today,
    )
    meta.save(dest_dir / ".override")
    _sync_custom_port_repo_and_sig(dest_dir)

    print(
        f"==> Forked {origin_collection}/{pkg} ({ver}-{rel} @ {origin_commit[:8]}) -> "
        f"ports/custom/custom-{category}/{pkg}"
    )
    return 0


def _append_source_to_pkgfile(pkgfile_text: str, patch_name: str) -> str:
    """Append patch_name to source=(...) in Pkgfile if not already present."""
    # Check if already in source=()
    if re.search(rf"\b{re.escape(patch_name)}\b", pkgfile_text):
        return pkgfile_text

    # Single-line source=(...)
    m_single = re.search(r"^(source=\([^\n)]*)\)", pkgfile_text, re.M)
    if m_single:
        start, end = m_single.span()
        inner = m_single.group(1)
        return pkgfile_text[:start] + f"{inner}\n    {patch_name})" + pkgfile_text[end:]

    # Multi-line source=( ... )
    m_multi = re.search(r"^source=\((.*?)\)", pkgfile_text, re.M | re.S)
    if m_multi:
        start, end = m_multi.span()
        body = m_multi.group(1).rstrip()
        return pkgfile_text[:start] + f"source=({body}\n    {patch_name})" + pkgfile_text[end:]

    raise ValueError("Could not locate source=(...) array in Pkgfile")


def _increment_pkgfile_release(pkgfile_text: str) -> tuple[str, int]:
    """Increment release=N in Pkgfile and return (updated_text, new_release)."""
    m = re.search(r"^release=(\d+)\b", pkgfile_text, re.M)
    if not m:
        raise ValueError("Could not locate 'release=<int>' in Pkgfile")
    new_rel = int(m.group(1)) + 1
    start, end = m.span()
    updated = pkgfile_text[:start] + f"release={new_rel}" + pkgfile_text[end:]
    return updated, new_rel


def _insert_patch_loop_in_build(pkgfile_text: str) -> tuple[str, bool]:
    """Ensure the CVE patch loop is present right after `cd ...` inside build().

    Returns (updated_text, ok). If build() does not fit the expected shape, returns (pkgfile_text, False).
    """
    if PATCH_LOOP_SNIPPET in pkgfile_text or "CVE-*.patch" in pkgfile_text:
        return pkgfile_text, True

    lines = pkgfile_text.splitlines()
    in_build = False
    cd_line_idx = -1
    indent = "    "

    for idx, line in enumerate(lines):
        if re.match(r"^\s*build\s*\(\)\s*\{", line):
            in_build = True
            continue
        if in_build:
            if re.match(r"^\}", line):
                break
            m_cd = re.match(r"^(\s*)cd\s+\S+", line)
            if m_cd:
                cd_line_idx = idx
                indent = m_cd.group(1) or "    "
                break

    if cd_line_idx < 0:
        return pkgfile_text, False

    lines.insert(cd_line_idx + 1, f"{indent}{PATCH_LOOP_SNIPPET}")
    return "\n".join(lines) + "\n", True


def cmd_patch(args: argparse.Namespace) -> int:
    """Attach a CVE patch to an override port, update Pkgfile and .override."""
    pkg = args.pkg.strip()
    cve_id = args.cve.strip().upper()
    if not vex.CVE_ID_RE.fullmatch(cve_id):
        print(f"ERROR: Invalid CVE identifier: {cve_id!r} (expected CVE-YYYY-NNNNN)", file=sys.stderr)
        return 1

    port_dir = _find_custom_override_dir(pkg)
    if port_dir is None:
        print(
            f"ERROR: No override found for '{pkg}' under ports/custom/ (run `vulntool override fork {pkg}` first)",
            file=sys.stderr,
        )
        return 1

    patch_filename = f"{cve_id}.patch"
    dest_patch = port_dir / patch_filename
    src_spec = args.patch_source.strip()

    if src_spec.startswith(("http://", "https://")):
        req = urllib.request.Request(src_spec, headers={"User-Agent": "irradium-vulntool/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            dest_patch.write_bytes(data)
        except Exception as exc:
            print(f"ERROR: Failed to download patch from {src_spec}: {exc}", file=sys.stderr)
            return 1
    else:
        src_path = pathlib.Path(src_spec).expanduser().resolve()
        if not src_path.is_file():
            print(f"ERROR: Patch file not found: {src_path}", file=sys.stderr)
            return 1
        if src_path != dest_patch:
            shutil.copyfile(src_path, dest_patch)

    pkgfile = port_dir / "Pkgfile"
    text = pkgfile.read_text(encoding="utf-8")
    try:
        text = _append_source_to_pkgfile(text, patch_filename)
        text, new_rel = _increment_pkgfile_release(text)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    text, ok = _insert_patch_loop_in_build(text)
    pkgfile.write_text(text, encoding="utf-8")

    meta_path = port_dir / ".override"
    meta = OverrideMeta.load(meta_path)
    if cve_id not in meta.cves:
        meta.cves.append(cve_id)
    if not meta.reason:
        meta.reason = cve_id
    elif cve_id not in meta.reason:
        meta.reason = f"{meta.reason},{cve_id}"
    if "upstream_has_cve_patch" not in meta.retire_when:
        meta.retire_when = (
            f"{meta.retire_when}|upstream_has_cve_patch"
            if meta.retire_when
            else "upstream_has_cve_patch"
        )
    meta.save(meta_path)
    _sync_custom_port_repo_and_sig(port_dir)

    if not ok:
        print(
            f"WARN: Added {patch_filename} to source=() and bumped release={new_rel}, "
            f"but build() in {pkgfile} has no standard `cd <srcdir>` line.\n"
            f"Please insert the patch loop manually in {pkgfile}:\n"
            f"    {PATCH_LOOP_SNIPPET}",
            file=sys.stderr,
        )
        return 1

    print(
        f"==> Patched {pkg} with {patch_filename} (release={new_rel}); "
        f"run `python3 -m vulntool override refresh {pkg}` to rebuild footprint and signature."
    )
    return 0


def cmd_bump(args: argparse.Namespace) -> int:
    """Bump an override port's upstream version and reset release=1."""
    pkg = args.pkg.strip()
    new_version = args.version.strip()

    port_dir = _find_custom_override_dir(pkg)
    if port_dir is None:
        print(
            f"ERROR: No override found for '{pkg}' under ports/custom/ (run `vulntool override fork {pkg}` first)",
            file=sys.stderr,
        )
        return 1

    pkgfile = port_dir / "Pkgfile"
    text = pkgfile.read_text(encoding="utf-8")
    if not re.search(r"^version=", text, re.M):
        print(f"ERROR: Could not find 'version=' line in {pkgfile}", file=sys.stderr)
        return 1

    text = re.sub(r"^version=.*$", f"version={new_version}", text, count=1, flags=re.M)
    text = re.sub(r"^release=.*$", "release=1", text, count=1, flags=re.M)
    pkgfile.write_text(text, encoding="utf-8")

    meta_path = port_dir / ".override"
    meta = OverrideMeta.load(meta_path)
    if getattr(args, "cve", None):
        for raw_cve in args.cve:
            for c in re.split(r"[, \t]+", raw_cve):
                cu = c.strip().upper()
                if cu and cu not in meta.cves:
                    meta.cves.append(cu)
    cond = f"upstream_version>={new_version}"
    parts = [
        p
        for p in meta.retire_when.split("|")
        if p and not p.startswith("upstream_version>=")
    ]
    parts.insert(0, cond)
    meta.retire_when = "|".join(parts)
    if not meta.reason:
        meta.reason = ",".join(meta.cves) if meta.cves else f"bump-{new_version}"
    meta.save(meta_path)
    _sync_custom_port_repo_and_sig(port_dir)

    print(
        f"==> Bumped {pkg} to version={new_version}, release=1 (retire_when={meta.retire_when}); "
        f"run `python3 -m vulntool override refresh {pkg}` to rebuild footprint and signature."
    )
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    """Refresh .footprint, .signature*, and collection REPO and verify CVEs are fixed."""
    pkg = args.pkg.strip()
    port_dir = _find_custom_override_dir(pkg)
    if port_dir is None:
        # Also allow refreshing original custom ports like notqmail if requested
        found = ports.find_port(pkg, include_custom=True)
        if found and found[0].startswith("custom-"):
            port_dir = found[2]
        else:
            print(f"ERROR: No custom port or override found for '{pkg}'", file=sys.stderr)
            return 1

    upstream_sigs = [s for s in sorted(port_dir.glob(".signature*")) if signify.is_upstream_signature_file(s)]
    if upstream_sigs:
        print(
            f"ERROR: {upstream_sigs[0]} in override port {pkg} is signed for an upstream collection; overrides must not retain upstream .signature* files",
            file=sys.stderr,
        )
        return 1

    arch = getattr(args, "arch", None) or ports.DEFAULT_ARCH
    distr = ports.DEFAULT_DISTR_VERSION
    docker_platform = "linux/riscv64" if arch == "riscv64" else "linux/arm64"
    image_name = f"irradium-{arch}:{distr}"
    cache_dir = ports.ROOT_DIR / "cache" / arch
    collection = port_dir.parent.name

    if not getattr(args, "skip_build", False):
        # Ensure builder image exists
        inspect = subprocess.run(
            ["docker", "image", "inspect", image_name],
            capture_output=True,
            check=False,
        )
        if inspect.returncode != 0:
            print(f"==> Building Docker image {image_name}...")
            subprocess.run(
                [str(ports.BUILDER_DIR / "build-pkg.sh"), "--arch", arch, "image"],
                check=True,
            )

        (cache_dir / "sources").mkdir(parents=True, exist_ok=True)
        (cache_dir / "packages").mkdir(parents=True, exist_ok=True)

        container_script = f"""
set -euo pipefail
mkdir -p /var/cache/pkgmk/sources /var/cache/pkgmk/packages /tmp/pkgmk-work
sed -i 's|PKGMK_WORK_DIR=.*|PKGMK_WORK_DIR="/tmp/pkgmk-work/$name"|' /etc/pkgmk.conf
cd "/mnt/ports/custom/{collection}/{pkg}"
echo "==> [REFRESH] Running pkgmk -d -uf for {collection}/{pkg}..."
pkgmk -d -uf
"""
        run_res = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-i",
                "--platform",
                docker_platform,
                "-v",
                f"{ports.PORTS_ROOT}:/mnt/ports",
                "-v",
                f"{cache_dir}:/var/cache/pkgmk",
                image_name,
                "/bin/bash",
                "-s",
            ],
            input=container_script,
            text=True,
            check=False,
        )
        if run_res.returncode != 0:
            print(f"ERROR: Builder container failed during refresh of {pkg}", file=sys.stderr)
            return run_res.returncode

    _sync_custom_port_repo_and_sig(port_dir)

    upstream_sigs = [s for s in sorted(port_dir.glob(".signature*")) if signify.is_upstream_signature_file(s)]
    if upstream_sigs:
        print(f"ERROR: Upstream {upstream_sigs[0]} exists after refresh", file=sys.stderr)
        return 1

    # Re-scan just this package to confirm target CVEs are gone
    meta_file = port_dir / ".override"
    target_cves: set[str] = set()
    if meta_file.is_file():
        meta = OverrideMeta.load(meta_file)
        target_cves = set(meta.cves)

    print(f"==> Re-scanning {pkg} to verify CVE resolution...")
    _, actionable, suppressed, _ = scan.run_scan(
        targets=[pkg],
        allow_fuzzy=True,
        offline=True,
    )
    remaining_target_cves = [f for f in actionable if f.cve in target_cves]
    if remaining_target_cves:
        for f in remaining_target_cves:
            print(
                f"ERROR: Target CVE {f.cve} ({f.severity}) is STILL actionable on {pkg} {f.version}-{f.release}",
                file=sys.stderr,
            )
        return 1

    if target_cves:
        print(f"==> Verified: target CVE(s) {', '.join(sorted(target_cves))} resolved on {pkg}.")

    diff_res = subprocess.run(
        ["git", "-C", str(ports.ROOT_DIR), "status", "-s", "--", str(port_dir.relative_to(ports.ROOT_DIR))],
        capture_output=True,
        text=True,
        check=False,
    )
    if diff_res.stdout.strip():
        print("==> Modified files in override:")
        print(diff_res.stdout.rstrip())
    return 0


def retire_override(pkg: str) -> tuple[bool, str]:
    """Delete an override port and restore packages/upstream.txt if was_prebuilt=yes."""
    port_dir = _find_custom_override_dir(pkg)
    if port_dir is None:
        return False, f"No override found for '{pkg}'"

    meta = OverrideMeta.load(port_dir / ".override")
    col_dir = port_dir.parent
    cat = col_dir.name.split("-")[-1]
    shutil.rmtree(port_dir)
    signify.update_collection_repo(col_dir, ensure_ignore_file=True)

    # Remove stale local override build archives from repo/ if upstream is now newer
    origin_dir = _resolve_origin_port_dir(meta.origin, pkg)
    if origin_dir is not None:
        up_ver, up_rel = ports.source_pkgfile(origin_dir)
        up_vr = f"{up_ver}-{up_rel}"
        pkgs_base = ports.REPO_ROOT / "irradium" / "packages"
        if pkgs_base.is_dir():
            for pkg_archive in pkgs_base.glob(f"*/*/{cat}/{pkg}#*.pkg.tar.*"):
                if pkg_archive.name.endswith(".sig"):
                    continue
                parsed = ports.parse_pkg_filename(pkg_archive.name)
                if parsed and versions.vercmp(f"{parsed[1]}-{parsed[2]}", up_vr) < 0:
                    pkg_archive.unlink(missing_ok=True)
                    pkg_archive.with_name(pkg_archive.name + ".sig").unlink(missing_ok=True)

    msg = f"Removed override directory {port_dir.relative_to(ports.ROOT_DIR)}"
    _remove_pkg_from_file(ports.BUILD_TXT, pkg)
    if meta.was_prebuilt:
        _add_pkg_to_file(ports.UPSTREAM_TXT, pkg)
        msg += f" and moved '{pkg}' back from packages/build.txt to packages/upstream.txt"
    else:
        msg += f" and removed '{pkg}' from packages/build.txt"
    return True, msg


def cmd_retire(args: argparse.Namespace) -> int:
    ok, msg = retire_override(args.pkg.strip())
    if not ok:
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1
    print(f"==> {msg}")
    return 0


@dataclasses.dataclass
class OverrideStatusItem:
    pkg: str
    collection: str
    override_version: str
    origin: str
    origin_commit: str
    origin_version: str
    upstream_commit: str
    upstream_version: str
    was_prebuilt: bool
    cves: list[str]
    retire_when: str
    created: str
    age_days: int
    state: str  # "retire" | "waiting_binary" | "drift" | "stale" | "active"
    reason_detail: str = ""
    upstream_diff: str = ""


def _evaluate_retire_when(
    retire_when: str,
    upstream_ver_rel: str,
    upstream_ver: str,
    upstream_patches: dict[str, list[str]],
    override_cves: list[str],
) -> tuple[bool, list[str]]:
    """Evaluate retire_when expressions combined with '|'."""
    clauses = [c.strip() for c in retire_when.split("|") if c.strip()]
    if not clauses:
        return False, []

    matched_reasons: list[str] = []
    for clause in clauses:
        if clause.startswith("upstream_version>="):
            target_v = clause.split(">=", 1)[1].strip()
            cmp_lhs = upstream_ver_rel if "-" in target_v else upstream_ver
            if versions.vercmp(cmp_lhs, target_v) >= 0:
                matched_reasons.append(f"upstream version {upstream_ver_rel} >= {target_v}")
        elif clause == "upstream_has_cve_patch":
            if override_cves:
                patched = [c for c in override_cves if c in upstream_patches]
                if patched and len(patched) == len(override_cves):
                    matched_reasons.append(
                        f"upstream has patch(es) for {', '.join(patched)}"
                    )
            elif upstream_patches:
                matched_reasons.append(
                    f"upstream has CVE patch(es) ({', '.join(sorted(upstream_patches.keys()))})"
                )

    return bool(matched_reasons), matched_reasons


def collect_override_statuses(
    stale_days: int = 30,
    offline: bool = False,
) -> list[OverrideStatusItem]:
    """Inspect all custom port overrides (.override) and classify their lifecycle status."""
    items: list[OverrideStatusItem] = []
    today = datetime.date.today()

    upstream_mirror_index: dict[str, tuple[str, str, str]] | None = None

    for cat in ports.CATEGORIES:
        custom_cat_dir = ports.PORTS_ROOT / "custom" / f"custom-{cat}"
        if not custom_cat_dir.is_dir():
            continue
        for port_dir in sorted(custom_cat_dir.iterdir(), key=lambda p: p.name):
            meta_file = port_dir / ".override"
            if not (port_dir / "Pkgfile").is_file() or not meta_file.is_file():
                continue

            pkg = port_dir.name
            meta = OverrideMeta.load(meta_file)
            ov_ver, ov_rel = ports.source_pkgfile(port_dir)
            override_version = f"{ov_ver}-{ov_rel}"

            origin_dir = _resolve_origin_port_dir(meta.origin, pkg)
            if origin_dir is None:
                items.append(
                    OverrideStatusItem(
                        pkg=pkg,
                        collection=f"custom-{cat}",
                        override_version=override_version,
                        origin=meta.origin,
                        origin_commit=meta.origin_commit,
                        origin_version=meta.origin_version,
                        upstream_commit="missing",
                        upstream_version="missing",
                        was_prebuilt=meta.was_prebuilt,
                        cves=meta.cves,
                        retire_when=meta.retire_when,
                        created=meta.created,
                        age_days=0,
                        state="active",
                        reason_detail="Upstream origin port not found",
                    )
                )
                continue

            up_ver, up_rel = ports.source_pkgfile(origin_dir)
            upstream_version = f"{up_ver}-{up_rel}"
            upstream_commit = _git_head_sha(origin_dir)
            upstream_patches = vex.discover_port_cve_patches(origin_dir)

            age_days = 0
            if meta.created:
                try:
                    created_dt = datetime.date.fromisoformat(meta.created)
                    age_days = max(0, (today - created_dt).days)
                except ValueError:
                    age_days = 0

            satisfied, reasons = _evaluate_retire_when(
                meta.retire_when,
                upstream_ver_rel=upstream_version,
                upstream_ver=up_ver,
                upstream_patches=upstream_patches,
                override_cves=meta.cves,
            )

            upstream_diff = ""
            if meta.origin_commit and meta.origin_commit != "unknown" and meta.origin_commit != upstream_commit:
                diff_proc = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(origin_dir),
                        "diff",
                        f"{meta.origin_commit}..HEAD",
                        "--",
                        ".",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if diff_proc.returncode == 0:
                    upstream_diff = diff_proc.stdout.strip()

            if satisfied:
                reason_str = "; ".join(reasons)
                if meta.was_prebuilt and not offline:
                    if upstream_mirror_index is None:
                        upstream_mirror_index = ports.fetch_upstream_irradium_index()
                    mir_info = upstream_mirror_index.get(pkg)
                    if not mir_info:
                        state = "waiting_binary"
                        reason_str += " (waiting for binary to appear on dl.irradium.org)"
                    else:
                        mir_ver, mir_rel, _ = mir_info
                        mir_ver_rel = f"{mir_ver}-{mir_rel}"
                        if versions.vercmp(mir_ver_rel, upstream_version) < 0:
                            state = "waiting_binary"
                            reason_str += (
                                f" (upstream mirror still has {mir_ver_rel}, waiting for {upstream_version})"
                            )
                        else:
                            state = "retire"
                            reason_str += f" (binary {mir_ver_rel} confirmed on upstream mirror)"
                else:
                    state = "retire"
            elif upstream_diff or upstream_version != meta.origin_version:
                state = "drift"
                reason_str = (
                    f"upstream changed ({meta.origin_version} @ {meta.origin_commit[:8]} -> "
                    f"{upstream_version} @ {upstream_commit[:8]}) but retire_when ({meta.retire_when}) not met"
                )
            elif age_days >= stale_days:
                state = "stale"
                reason_str = f"override is {age_days} days old (created {meta.created}) with no upstream movement"
            else:
                state = "active"
                reason_str = f"active ({age_days}d old, waiting for {meta.retire_when})"

            items.append(
                OverrideStatusItem(
                    pkg=pkg,
                    collection=f"custom-{cat}",
                    override_version=override_version,
                    origin=meta.origin,
                    origin_commit=meta.origin_commit,
                    origin_version=meta.origin_version,
                    upstream_commit=upstream_commit,
                    upstream_version=upstream_version,
                    was_prebuilt=meta.was_prebuilt,
                    cves=meta.cves,
                    retire_when=meta.retire_when,
                    created=meta.created,
                    age_days=age_days,
                    state=state,
                    reason_detail=reason_str,
                    upstream_diff=upstream_diff,
                )
            )

    return items


def _apply_github_override_actions(items: list[OverrideStatusItem]) -> None:
    """Open deduplicated retire PRs or drift/stale GitHub issues for overrides (Section 2.4)."""
    for item in items:
        if item.state == "retire":
            pr_branch = f"retire-override-{item.pkg}"
            pr_check = subprocess.run(
                ["gh", "pr", "list", "--head", pr_branch, "--state", "open", "--json", "number,url"],
                cwd=str(ports.ROOT_DIR),
                capture_output=True,
                text=True,
                check=False,
            )
            if pr_check.returncode == 0 and pr_check.stdout.strip() not in ("", "[]"):
                print(f"==> Retire PR already open for {item.pkg} ({pr_branch}); skipping.", file=sys.stderr)
                continue

            print(f"==> Preparing retire PR for {item.pkg}...", file=sys.stderr)
            cur_branch_proc = subprocess.run(
                ["git", "-C", str(ports.ROOT_DIR), "branch", "--show-current"],
                capture_output=True,
                text=True,
                check=False,
            )
            base_branch = cur_branch_proc.stdout.strip() or ports.DEFAULT_DISTR_VERSION

            subprocess.run(
                ["git", "-C", str(ports.ROOT_DIR), "checkout", "-B", pr_branch],
                check=False,
            )
            ok, retire_msg = retire_override(item.pkg)
            if not ok:
                subprocess.run(["git", "-C", str(ports.ROOT_DIR), "checkout", base_branch], check=False)
                continue

            # Run clean scan of upstream version
            scan_rc, actionable, _, _ = scan.run_scan(targets=[item.pkg], allow_fuzzy=True, offline=True)
            if scan_rc != 0 or actionable:
                print(
                    f"WARN: Upstream version of {item.pkg} still has actionable findings; aborting retire PR",
                    file=sys.stderr,
                )
                subprocess.run(["git", "-C", str(ports.ROOT_DIR), "checkout", "--", "."], check=False)
                subprocess.run(["git", "-C", str(ports.ROOT_DIR), "checkout", base_branch], check=False)
                continue

            subprocess.run(["git", "-C", str(ports.ROOT_DIR), "add", "-A"], check=False)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(ports.ROOT_DIR),
                    "commit",
                    "-m",
                    f"chore(override): retire {item.pkg} override (upstream at {item.upstream_version})",
                ],
                check=False,
            )
            push_res = subprocess.run(
                ["git", "-C", str(ports.ROOT_DIR), "push", "-u", "origin", pr_branch, "--force"],
                capture_output=True,
                text=True,
                check=False,
            )
            if push_res.returncode == 0:
                pr_body = (
                    f"### Retire Override: `{item.pkg}`\n\n"
                    f"- **Origin:** `{item.origin}`\n"
                    f"- **Override Version:** `{item.override_version}`\n"
                    f"- **Upstream Version:** `{item.upstream_version}` (`{item.upstream_commit[:8]}`)\n"
                    f"- **Condition Met:** {item.reason_detail}\n"
                    f"- **Action:** {retire_msg}\n"
                )
                pr_res = subprocess.run(
                    [
                        "gh",
                        "pr",
                        "create",
                        "--base",
                        base_branch,
                        "--head",
                        pr_branch,
                        "--title",
                        f"chore(override): retire {item.pkg} override ({item.upstream_version})",
                        "--body",
                        pr_body,
                    ],
                    cwd=str(ports.ROOT_DIR),
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if pr_res.returncode == 0:
                    print(f"==> Opened retire PR for {item.pkg}: {pr_res.stdout.strip()}", file=sys.stderr)
                else:
                    err_msg = pr_res.stderr.strip() or pr_res.stdout.strip()
                    print(
                        f"WARN: Could not create retire PR for {item.pkg} ({pr_branch}): {err_msg}",
                        file=sys.stderr,
                    )
                    tag = f"[override:retire] {item.pkg}"
                    issue_check = subprocess.run(
                        [
                            "gh",
                            "issue",
                            "list",
                            "--state",
                            "open",
                            "--search",
                            f"{tag} in:title",
                            "--json",
                            "number,title",
                        ],
                        cwd=str(ports.ROOT_DIR),
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if issue_check.returncode == 0 and issue_check.stdout.strip() in ("", "[]"):
                        issue_title = f"{tag}: ready to retire (upstream at {item.upstream_version})"
                        issue_body = (
                            f"{pr_body}\n"
                            f"> **Note:** Branch `{pr_branch}` was pushed, but automatic PR creation failed:\n"
                            f"> `{err_msg}`\n"
                        )
                        subprocess.run(
                            ["gh", "issue", "create", "--title", issue_title, "--body", issue_body],
                            cwd=str(ports.ROOT_DIR),
                            check=False,
                        )
            else:
                print(
                    f"WARN: Failed to push {pr_branch}: {push_res.stderr.strip()}",
                    file=sys.stderr,
                )
            subprocess.run(["git", "-C", str(ports.ROOT_DIR), "checkout", base_branch], check=False)

        elif item.state in ("drift", "stale"):
            tag = f"[override:{item.state}] {item.pkg}"
            check = subprocess.run(
                [
                    "gh",
                    "issue",
                    "list",
                    "--state",
                    "open",
                    "--search",
                    f"{tag} in:title",
                    "--json",
                    "number,title",
                ],
                cwd=str(ports.ROOT_DIR),
                capture_output=True,
                text=True,
                check=False,
            )
            if check.returncode == 0 and check.stdout.strip() not in ("", "[]"):
                continue

            if item.state == "drift":
                title = f"{tag}: upstream updated to {item.upstream_version} (still unfixed)"
                diff_block = f"```diff\n{item.upstream_diff}\n```\n" if item.upstream_diff else "_No diff output_"
                body = (
                    f"### Override Drift Detected: `{item.pkg}`\n\n"
                    f"- **Origin:** `{item.origin}`\n"
                    f"- **Forked From:** `{item.origin_version}` (`{item.origin_commit[:8]}`)\n"
                    f"- **Current Upstream:** `{item.upstream_version}` (`{item.upstream_commit[:8]}`)\n"
                    f"- **Retire Condition:** `{item.retire_when}`\n"
                    f"- **Status:** {item.reason_detail}\n\n"
                    f"#### Upstream Diff (`{item.origin_commit[:8]}..{item.upstream_commit[:8]}`)\n\n"
                    f"{diff_block}"
                )
            else:
                title = f"{tag}: override is {item.age_days} days old with no upstream movement"
                body = (
                    f"### Stale Override Reminder: `{item.pkg}`\n\n"
                    f"- **Origin:** `{item.origin}`\n"
                    f"- **Override Version:** `{item.override_version}`\n"
                    f"- **CVEs:** `{', '.join(item.cves) if item.cves else 'n/a'}`\n"
                    f"- **Created:** `{item.created}` ({item.age_days} days ago)\n"
                    f"- **Retire Condition:** `{item.retire_when}`\n\n"
                    f"Consider reporting or following up on the fix with upstream CRUX / Irradium."
                )

            subprocess.run(
                ["gh", "issue", "create", "--title", title, "--body", body],
                cwd=str(ports.ROOT_DIR),
                check=False,
            )


def cmd_status(args: argparse.Namespace) -> int:
    """Report status (retire / drift / stale / active) for all local port overrides."""
    stale_days = getattr(args, "stale_days", 30)
    offline = getattr(args, "offline", False)
    items = collect_override_statuses(stale_days=stale_days, offline=offline)

    if getattr(args, "json", False):
        print(json.dumps([dataclasses.asdict(i) for i in items], indent=2))
    else:
        if not items:
            print("==> No active overrides (.override) found under ports/custom/.")
        else:
            print(f"==> Override Status ({len(items)} override(s)):")
            for item in items:
                cves_str = ",".join(item.cves) if item.cves else "-"
                print(
                    f"  [{item.state.upper()}] {item.collection}/{item.pkg} ({item.override_version}) "
                    f"<- {item.origin} ({item.upstream_version}) | CVEs: {cves_str} | {item.reason_detail}"
                )
                if item.state == "drift" and item.upstream_diff and getattr(args, "show_diff", True):
                    for dline in item.upstream_diff.splitlines()[:40]:
                        print(f"      {dline}")

    if getattr(args, "apply_github", False) and items:
        _apply_github_override_actions(items)

    return 0
