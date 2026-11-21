"""In-container build and upstream sync runner executed inside the Irradium builder container."""

from __future__ import annotations

import concurrent.futures
import os
import pathlib
import re
import shutil
import ssl
import subprocess
import sys
import urllib.parse
import urllib.request

from vulntool import versions

from . import signify

IRRADIUM_UPSTREAM_PUB = """untrusted comment: pkg-get public key
RWTuJkODJcOmD4iSbIIUzRt+qT73ua9l6E916KuyYLp4qc5MM42EMIp0
"""

UPSTREAM_PUB_PATH = pathlib.Path("/tmp/irradium-upstream.pub")

PRT_GET_CONF = """prtdir /usr/ports/custom-core
prtdir /usr/ports/custom-opt
prtdir /usr/ports/custom-xorg
prtdir /usr/ports/custom-xfce
prtdir /usr/ports/custom-contrib
prtdir /usr/ports/irradium-core
prtdir /usr/ports/irradium-opt
prtdir /usr/ports/irradium-xorg
prtdir /usr/ports/irradium-xfce
prtdir /usr/ports/irradium-contrib
prtdir /usr/ports/core
prtdir /usr/ports/opt
prtdir /usr/ports/xorg
prtdir /usr/ports/contrib
"""

PRT_ORDER: list[tuple[str, str]] = [
    ("core", "/usr/ports/custom-core"),
    ("opt", "/usr/ports/custom-opt"),
    ("xorg", "/usr/ports/custom-xorg"),
    ("xfce", "/usr/ports/custom-xfce"),
    ("contrib", "/usr/ports/custom-contrib"),
    ("core", "/usr/ports/irradium-core"),
    ("opt", "/usr/ports/irradium-opt"),
    ("xorg", "/usr/ports/irradium-xorg"),
    ("xfce", "/usr/ports/irradium-xfce"),
    ("contrib", "/usr/ports/irradium-contrib"),
    ("core", "/usr/ports/core"),
    ("opt", "/usr/ports/opt"),
    ("xorg", "/usr/ports/xorg"),
    ("contrib", "/usr/ports/contrib"),
]

CATEGORIES = ["core", "opt", "xorg", "xfce", "contrib"]
TARGET_NAME_RE = re.compile(r"^[a-zA-Z0-9._+-]+(/[a-zA-Z0-9._+-]+)?$")


def _create_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    extra_ca = pathlib.Path("/usr/local/share/ca-certificates/zerossl-sectigo-intermediates.crt")
    if extra_ca.is_file():
        try:
            ctx.load_verify_locations(cafile=str(extra_ca))
        except Exception:
            pass
    return ctx


def _upstream_mirrors(arch: str, distr: str) -> list[str]:
    return [
        f"https://mirror.accum.se/mirror/irradium.org/packages/{arch}/{distr}",
        f"https://ftp.cc.uoc.gr/mirrors/linux/irradium/packages/{arch}/{distr}",
        f"https://dl.irradium.org/irradium/packages/{arch}/{distr}",
    ]


def _setup_container_environment() -> None:
    """Initialize directories, CA bundle, upstream pubkey, and /usr/ports symlinks inside the container."""
    for d in (
        "/var/cache/pkgmk/sources",
        "/var/cache/pkgmk/packages",
        "/tmp/pkgmk-work",
        "/usr/ports",
        "/etc/ports",
    ):
        os.makedirs(d, exist_ok=True)

    pkgmk_conf = pathlib.Path("/etc/pkgmk.conf")
    if pkgmk_conf.is_file():
        text = pkgmk_conf.read_text(encoding="utf-8", errors="replace")
        text = re.sub(
            r"^PKGMK_WORK_DIR=.*$",
            'PKGMK_WORK_DIR="/tmp/pkgmk-work/$name"',
            text,
            flags=re.M,
        )
        pkgmk_conf.write_text(text, encoding="utf-8")

    # Ensure ZeroSSL/Sectigo intermediate CA certs are in system bundle for dl.irradium.org TLS verification
    extra_ca = pathlib.Path("/usr/local/share/ca-certificates/zerossl-sectigo-intermediates.crt")
    if extra_ca.is_file():
        ca_pem = extra_ca.read_text(encoding="utf-8", errors="replace")
        for bundle_str in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
            bundle = pathlib.Path(bundle_str)
            if bundle.is_file():
                cur = bundle.read_text(encoding="utf-8", errors="replace")
                if "MIIDNTCCArugAwIBAgIRAMThxbsA8CePNHvk" not in cur:
                    with bundle.open("a", encoding="utf-8") as f:
                        f.write("\n" + ca_pem.strip() + "\n")

    UPSTREAM_PUB_PATH.write_text(IRRADIUM_UPSTREAM_PUB, encoding="utf-8")

    # Install custom-*.pub keys in /etc/ports so custom port .signature files can be verified
    pkg_get_pub = pathlib.Path("/etc/pkg-get/pkg-get.pub")
    if pkg_get_pub.is_file():
        for c in CATEGORIES:
            shutil.copyfile(pkg_get_pub, f"/etc/ports/custom-{c}.pub")

    pathlib.Path("/etc/prt-get.conf").write_text(PRT_GET_CONF, encoding="utf-8")

    for c in ("core", "opt", "xorg", "xfce", "contrib"):
        custom_mnt = pathlib.Path(f"/mnt/ports/custom/custom-{c}")
        custom_mnt.mkdir(parents=True, exist_ok=True)
        custom_link = pathlib.Path(f"/usr/ports/custom-{c}")
        if custom_link.is_symlink() or custom_link.exists():
            if custom_link.is_dir() and not custom_link.is_symlink():
                shutil.rmtree(custom_link)
            else:
                custom_link.unlink()
        custom_link.symlink_to(custom_mnt)

        irr_mnt = pathlib.Path(f"/mnt/ports/irradium/irradium-{c}")
        irr_link = pathlib.Path(f"/usr/ports/irradium-{c}")
        if irr_mnt.is_dir():
            if irr_link.is_symlink() or irr_link.exists():
                if irr_link.is_dir() and not irr_link.is_symlink():
                    shutil.rmtree(irr_link)
                else:
                    irr_link.unlink()
            irr_link.symlink_to(irr_mnt)
        else:
            irr_link.mkdir(parents=True, exist_ok=True)

    for c in ("core", "opt", "xorg", "contrib"):
        crux_mnt = pathlib.Path(f"/mnt/ports/crux-{c}")
        crux_link = pathlib.Path(f"/usr/ports/{c}")
        if crux_mnt.is_dir():
            if crux_link.is_symlink() or crux_link.exists():
                if crux_link.is_dir() and not crux_link.is_symlink():
                    shutil.rmtree(crux_link)
                else:
                    crux_link.unlink()
            crux_link.symlink_to(crux_mnt)
        else:
            crux_link.mkdir(parents=True, exist_ok=True)


def _read_installed_packages() -> set[str]:
    installed: set[str] = set()
    db_file = pathlib.Path("/var/lib/pkg/db")
    if not db_file.is_file():
        return installed
    lines = db_file.read_text(encoding="utf-8", errors="replace").splitlines()
    i = 0
    while i < len(lines):
        pkgname = lines[i].strip()
        if pkgname:
            installed.add(pkgname)
        i += 2
        while i < len(lines) and lines[i].strip():
            i += 1
        i += 1
    return installed


def _ver_rel_from_pkg_filename(fname: str) -> str:
    unquoted = urllib.parse.unquote(fname.split("/")[-1])
    rest = unquoted.split("#", 1)[-1]
    return re.sub(r"\.pkg\.tar\.[a-z0-9]+$", "", rest)


def _pick_newest_pkg_filename(candidates: list[str]) -> str:
    """Return the candidate filename with the highest version-release using versions.vercmp."""
    best = candidates[0]
    best_vr = _ver_rel_from_pkg_filename(best)
    for cand in candidates[1:]:
        cand_vr = _ver_rel_from_pkg_filename(cand)
        if versions.vercmp(cand_vr, best_vr) > 0:
            best = cand
            best_vr = cand_vr
    return best


def _sync_upstream_targets(
    targets: list[str],
    arch: str,
    distr: str,
    skip_existing: bool,
    mirror_url: str,
    ssl_ctx: ssl.SSLContext,
) -> int:
    """Fast parallel sync for all upstream:* targets."""
    if not targets:
        return 0

    upstream_mirrors = _upstream_mirrors(arch, distr)
    active_upstream: str | None = None
    for cand in upstream_mirrors:
        try:
            with urllib.request.urlopen(f"{cand}/core/", timeout=10, context=ssl_ctx) as r:
                if r.status == 200:
                    active_upstream = cand
                    break
        except Exception:
            continue

    if not active_upstream:
        print("ERROR: All upstream Irradium mirrors are unreachable", file=sys.stderr, flush=True)
        return 1

    upstream_index: dict[str, tuple[str, str, str]] = {}  # pkg_name -> (upstream_cat, fname, encoded_fname)

    def fetch_upstream_cat(cat: str) -> tuple[str, dict[str, tuple[str, str, str]]]:
        url = f"{active_upstream}/{cat}/"
        with urllib.request.urlopen(url, timeout=30, context=ssl_ctx) as r:
            if r.status != 200:
                raise RuntimeError(f"HTTP {r.status} fetching {url}")
            html = r.read().decode("utf-8", errors="replace")
        found: dict[str, tuple[str, str, str]] = {}
        for m in re.finditer(r'href="([^"]+\.pkg\.tar\.gz)"', html):
            raw_href = m.group(1).split("/")[-1]
            fname = urllib.parse.unquote(raw_href)
            name = fname.split("#", 1)[0]
            encoded = urllib.parse.quote(fname)
            if name not in found or versions.vercmp(
                _ver_rel_from_pkg_filename(fname),
                _ver_rel_from_pkg_filename(found[name][1]),
            ) > 0:
                found[name] = (cat, fname, encoded)
        if not found:
            raise RuntimeError(f"Upstream category listing {url} returned 0 packages")
        return cat, found

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for _cat, found in ex.map(fetch_upstream_cat, CATEGORIES):
            for name, info in found.items():
                if name not in upstream_index or versions.vercmp(
                    _ver_rel_from_pkg_filename(info[1]),
                    _ver_rel_from_pkg_filename(upstream_index[name][1]),
                ) > 0:
                    upstream_index[name] = info

    mirror_existing: set[str] = set()
    if skip_existing:
        def fetch_mirror_cat(cat: str) -> set[str]:
            for suffix in ("index.html", ""):
                url = f"{mirror_url}/{cat}/{suffix}"
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "irradium-packages/1.0"})
                    with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as r:
                        html = r.read().decode("utf-8", errors="replace")
                    items: set[str] = set()
                    for m in re.finditer(r'href="([^"]+\.pkg\.tar\.gz)"', html):
                        fname = urllib.parse.unquote(m.group(1).split("/")[-1])
                        items.add(f"{cat}/{fname}")
                    return items
                except Exception as exc:
                    print(f"WARN: Failed to query mirror index {url}: {exc}", file=sys.stderr, flush=True)
                    continue
            return set()

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            for items in ex.map(fetch_mirror_cat, CATEGORIES):
                mirror_existing |= items

    port_map: dict[str, tuple[str, list[str]]] = {}
    for cat, dpath in PRT_ORDER:
        pdir = pathlib.Path(dpath)
        if not pdir.is_dir():
            continue
        for child in pdir.iterdir():
            pkgfile = child / "Pkgfile"
            if child.name not in port_map and pkgfile.is_file():
                deps: list[str] = []
                try:
                    for line in pkgfile.read_text(encoding="utf-8", errors="replace").splitlines():
                        m = re.match(r"^#\s*Depends\s+on\s*:\s*(.*)$", line, re.I)
                        if m:
                            deps = [x.strip() for x in re.split(r"[, \t]+", m.group(1)) if x.strip()]
                            break
                except Exception:
                    pass
                port_map[child.name] = (cat, deps)

    installed_base = _read_installed_packages()

    def resolve_dep_order(root_pkg: str) -> list[str]:
        order: list[str] = []
        visited: set[str] = set()

        def dfs(pkg: str) -> None:
            if pkg in visited:
                return
            visited.add(pkg)
            if pkg in port_map:
                for dep in port_map[pkg][1]:
                    if dep in port_map and dep not in installed_base:
                        dfs(dep)
            order.append(pkg)

        dfs(root_pkg)
        return order

    to_sync: list[str] = []
    queued: set[str] = set()

    for t in targets:
        pkg_name = t.split("/")[-1]
        if pkg_name not in port_map:
            print(f"==> [UPSTREAM:UNAVAILABLE] {pkg_name} not found in port trees (skipping)", flush=True)
            continue
        if pkg_name not in upstream_index:
            print(f"==> [UPSTREAM:UNAVAILABLE] {pkg_name} has no pre-built {arch} binary on upstream mirror (skipping)", flush=True)
            continue
        dep_chain = resolve_dep_order(pkg_name)
        missing_deps = [d for d in dep_chain if d not in upstream_index]
        if missing_deps:
            print(
                f"==> [UPSTREAM:UNAVAILABLE] {pkg_name} missing dependency {missing_deps[0]} on upstream {arch} mirror (skipping)",
                flush=True,
            )
            continue
        for d in dep_chain:
            if d not in queued:
                queued.add(d)
                to_sync.append(d)

    def sync_one(pkg_name: str) -> str:
        upstream_cat, pkg_file, encoded_pkg = upstream_index[pkg_name]
        category = port_map[pkg_name][0] if pkg_name in port_map else upstream_cat
        repo_cat_dir = pathlib.Path(f"/repo/{category}")
        repo_cat_dir.mkdir(parents=True, exist_ok=True)
        dest_pkg = repo_cat_dir / pkg_file
        dest_sig = repo_cat_dir / f"{pkg_file}.sig"

        if skip_existing:
            if dest_pkg.is_file() and dest_sig.is_file():
                return f"==> [UPSTREAM:SKIP] {category}/{pkg_file} already exists locally"
            if f"{category}/{pkg_file}" in mirror_existing:
                return f"==> [UPSTREAM:SKIP] {category}/{pkg_file} already published on {mirror_url}"

        cache_pkg = pathlib.Path(f"/var/cache/pkgmk/packages/{pkg_file}")
        cache_sig = pathlib.Path(f"/var/cache/pkgmk/packages/{pkg_file}.upstream.sig")

        pkg_url = f"{active_upstream}/{upstream_cat}/{encoded_pkg}"
        sig_url = f"{pkg_url}.sig"

        with urllib.request.urlopen(pkg_url, timeout=120, context=ssl_ctx) as r, cache_pkg.open("wb") as f:
            shutil.copyfileobj(r, f)
        with urllib.request.urlopen(sig_url, timeout=30, context=ssl_ctx) as r, cache_sig.open("wb") as f:
            shutil.copyfileobj(r, f)

        subprocess.run(
            ["signify", "-p", str(UPSTREAM_PUB_PATH), "-V", "-q", "-m", str(cache_pkg), "-x", str(cache_sig)],
            check=True,
        )
        shutil.copy2(cache_pkg, dest_pkg)
        subprocess.run(
            ["signify", "-s", "/etc/pkg-get/pkg-get.sec", "-S", "-m", str(dest_pkg), "-x", str(dest_sig)],
            check=True,
        )
        subprocess.run(
            ["signify", "-p", "/etc/pkg-get/pkg-get.pub", "-V", "-q", "-m", str(dest_pkg), "-x", str(dest_sig)],
            check=True,
        )
        cache_pkg.unlink(missing_ok=True)
        cache_sig.unlink(missing_ok=True)
        return f"==> [UPSTREAM] Verified & re-signed: {category}/{pkg_file}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for msg in ex.map(sync_one, to_sync):
            print(msg, flush=True)

    return 0


def _prt_get_isinst(name: str) -> bool:
    res = subprocess.run(
        ["prt-get", "isinst", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return res.returncode == 0


def _prt_get_path(name: str) -> pathlib.Path | None:
    res = subprocess.run(
        ["prt-get", "path", name],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode == 0 and res.stdout.strip():
        p = pathlib.Path(res.stdout.strip())
        if (p / "Pkgfile").is_file():
            return p
    return None


def _prt_get_depends_uninstalled(name: str) -> list[str]:
    res = subprocess.run(
        ["prt-get", "depends", name],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0 or not res.stdout.strip() or "not found" in res.stdout:
        return []
    deps: list[str] = []
    for line in res.stdout.splitlines():
        m = re.search(r"\[\ \]\ ([^\s]+)", line)
        if m:
            deps.append(m.group(1))
    return deps


def _source_pkgfile_meta(port_dir: pathlib.Path) -> tuple[str, str, str]:
    """Source Pkgfile in bash and return (name, version, release)."""
    res = subprocess.run(
        ["bash", "-c", '. ./Pkgfile && printf "%s\\t%s\\t%s\\n" "$name" "$version" "$release"'],
        cwd=str(port_dir),
        capture_output=True,
        text=True,
        check=True,
    )
    parts = res.stdout.splitlines()[-1].split("\t")
    return parts[0].strip(), parts[1].strip(), parts[2].strip()


def _http_head_ok(url: str, ssl_ctx: ssl.SSLContext, timeout: float = 15.0) -> bool:
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "irradium-packages/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as r:
            return r.status == 200
    except Exception:
        return False


def _download_file(url: str, dest: pathlib.Path, ssl_ctx: ssl.SSLContext, timeout: float = 120.0) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "irradium-packages/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as r, dest.open("wb") as f:
        shutil.copyfileobj(r, f)


def _find_matching_pkg_in_html(url: str, pkg_name: str, ssl_ctx: ssl.SSLContext) -> str | None:
    """Fetch an HTML directory listing and return the newest matching href for `<pkg_name>#*.pkg.tar.gz`."""
    req = urllib.request.Request(url, headers={"User-Agent": "irradium-packages/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as r:
            if r.status != 200:
                return None
            html = r.read().decode("utf-8", errors="replace")
    except Exception:
        return None

    esc = re.escape(pkg_name)
    pat = re.compile(rf'href="((?:{esc}%23|{esc}#)[^"]+\.pkg\.tar\.gz)"')
    matches = [m.group(1) for m in pat.finditer(html)]
    if not matches:
        return None
    return _pick_newest_pkg_filename(matches)


def _find_missing_implicit_ports(arch: str) -> list[str]:
    """Scan installed .pc files and shared libraries for missing dependencies and map them to ports."""
    installed_pkgs = _read_installed_packages()

    # 1. Collect missing pkg-config modules from installed .pc files (Requires & Requires.private)
    pc_dirs = ["/usr/lib/pkgconfig", "/usr/share/pkgconfig", "/usr/lib64/pkgconfig"]
    installed_pcs: set[str] = set()
    pc_files: list[str] = []
    for d in pc_dirs:
        if os.path.isdir(d):
            for entry in os.scandir(d):
                if entry.name.endswith(".pc") and (entry.is_file() or entry.is_symlink()):
                    installed_pcs.add(entry.name[:-3])
                    pc_files.append(entry.path)

    var_re = re.compile(r"^([A-Za-z0-9_]+)\s*=\s*(.*)$")
    req_re = re.compile(r"^Requires(?:\.private)?\s*:\s*(.*)$")
    ver_constraint_re = re.compile(r"(?:<=|>=|!=|=|<|>)\s*[^\s,]+")
    var_ref_re = re.compile(r"\$\{([A-Za-z0-9_]+)\}")

    missing_pcs: set[str] = set()
    for pc_path in pc_files:
        try:
            text = pathlib.Path(pc_path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        text = text.replace("\\\n", " ")
        pc_vars: dict[str, str] = {}
        req_lines: list[str] = []
        for raw_line in text.splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            m_var = var_re.match(line)
            if m_var:
                k, v = m_var.group(1), m_var.group(2).strip()
                pc_vars[k] = var_ref_re.sub(lambda m: pc_vars.get(m.group(1), ""), v)
                continue
            m_req = req_re.match(line)
            if m_req:
                req_lines.append(m_req.group(1))
        for req_str in req_lines:
            expanded = var_ref_re.sub(lambda m: pc_vars.get(m.group(1), ""), req_str)
            cleaned = ver_constraint_re.sub(" ", expanded)
            for tok in re.split(r"[\s,]+", cleaned.strip()):
                if tok and not tok.startswith("$") and tok not in installed_pcs:
                    missing_pcs.add(tok + ".pc")

    # 2. Collect missing DT_NEEDED shared libraries from /lib, /usr/lib, and ELF binaries in /bin, /usr/bin
    lib_dirs = ["/lib", "/usr/lib", "/lib64", "/usr/lib64"]
    bin_dirs = ["/bin", "/usr/bin", "/sbin", "/usr/sbin"]
    installed_sos: set[str] = set()
    elf_paths: list[str] = []
    seen_realpaths: set[str] = set()
    for d in lib_dirs:
        if os.path.isdir(d):
            for entry in os.scandir(d):
                if ".so" in entry.name and (entry.is_file() or entry.is_symlink()):
                    installed_sos.add(entry.name)
                    if entry.is_file(follow_symlinks=True):
                        rp = os.path.realpath(entry.path)
                        if rp not in seen_realpaths:
                            seen_realpaths.add(rp)
                            elf_paths.append(entry.path)
    for d in bin_dirs:
        if os.path.isdir(d):
            for entry in os.scandir(d):
                if entry.is_file(follow_symlinks=True):
                    rp = os.path.realpath(entry.path)
                    if rp in seen_realpaths:
                        continue
                    try:
                        with open(entry.path, "rb") as f:
                            if f.read(4) == b"\x7fELF":
                                seen_realpaths.add(rp)
                                elf_paths.append(entry.path)
                    except OSError:
                        continue

    missing_sos: set[str] = set()
    if elf_paths:
        try:
            res = subprocess.run(
                ["readelf", "-d", *elf_paths],
                capture_output=True,
                text=True,
                check=False,
            )
            for m in re.finditer(r"\(NEEDED\)\s+Shared library:\s+\[([^\]]+)\]", res.stdout):
                soname = m.group(1)
                if soname not in installed_sos:
                    missing_sos.add(soname)
        except OSError:
            pass

    if not missing_pcs and not missing_sos:
        return []

    # 3. Map missing .pc and .so files to ports via /usr/ports/*/*/.footprint(.<arch>) in prt-get priority order
    seen_port_defs: set[str] = set()
    pc_to_port: dict[str, str] = {}
    so_to_port: dict[str, str] = {}
    for _cat, col_path in PRT_ORDER:
        col_dir = pathlib.Path(col_path)
        if not col_dir.is_dir():
            continue
        for port_dir in col_dir.iterdir():
            pkg = port_dir.name
            if pkg in seen_port_defs:
                continue
            fp = port_dir / f".footprint.{arch}"
            if not fp.is_file():
                fp = port_dir / ".footprint"
            if not fp.is_file():
                continue
            seen_port_defs.add(pkg)
            try:
                lines = fp.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for line in lines:
                parts = line.split("\t")
                if len(parts) < 3:
                    continue
                f_path = parts[2].split(" -> ", 1)[0].strip().lstrip("/")
                dirname = os.path.dirname(f_path)
                basename = os.path.basename(f_path)
                if dirname in ("usr/lib/pkgconfig", "usr/share/pkgconfig", "usr/lib64/pkgconfig") and basename in missing_pcs:
                    pc_to_port.setdefault(basename, pkg)
                elif dirname in ("lib", "usr/lib", "lib64", "usr/lib64") and basename in missing_sos:
                    so_to_port.setdefault(basename, pkg)

    return sorted((set(pc_to_port.values()) | set(so_to_port.values())) - installed_pkgs)


class ContainerBuilder:
    def __init__(
        self,
        arch: str,
        distr: str,
        skip_existing: bool,
        mirror_url: str,
        ssl_ctx: ssl.SSLContext,
    ) -> None:
        self.arch = arch
        self.distr = distr
        self.skip_existing = skip_existing
        self.mirror_url = mirror_url.rstrip("/")
        self.ssl_ctx = ssl_ctx
        self.invalid_remote_pkgs: set[str] = set()
        self._in_implicit_deps: bool = False

    def check_target_already_built(self, port_dir: pathlib.Path) -> bool:
        """Check if a target port is already built and validly signed locally or on the mirror."""
        if not self.skip_existing:
            return False
        collection = port_dir.parent.name
        category = collection.split("-")[-1]
        name, version, release = _source_pkgfile_meta(port_dir)
        pkg_file = f"{name}#{version}-{release}.pkg.tar.gz"
        encoded_pkg = f"{name}%23{version}-{release}.pkg.tar.gz"
        return self.check_existing(
            category=category,
            name=name,
            pkg_file=pkg_file,
            encoded_pkg=encoded_pkg,
            mode_label="BUILD",
            allow_any_version=False,
            install_if_skipped=False,
        )

    def check_existing(
        self,
        category: str,
        name: str,
        pkg_file: str,
        encoded_pkg: str,
        mode_label: str,
        allow_any_version: bool = False,
        install_if_skipped: bool = True,
    ) -> bool:
        if not self.skip_existing and not allow_any_version:
            return False

        local_pkg = pathlib.Path(f"/repo/{category}/{pkg_file}")
        local_sig = pathlib.Path(f"/repo/{category}/{pkg_file}.sig")
        if local_pkg.is_file() and local_sig.is_file():
            verify_local = subprocess.run(
                ["signify", "-p", "/etc/pkg-get/pkg-get.pub", "-V", "-q", "-m", str(local_pkg), "-x", str(local_sig)],
                check=False,
            )
            if verify_local.returncode == 0:
                print(f"==> [{mode_label}:SKIP] {category}/{pkg_file} already exists locally", flush=True)
                if install_if_skipped and not _prt_get_isinst(name):
                    subprocess.run(["pkgadd", str(local_pkg)], check=True)
                return True
            print(
                f"==> [{mode_label}:WARN] Local {category}/{pkg_file} failed signature verification; rebuilding...",
                flush=True,
            )
            local_pkg.unlink(missing_ok=True)
            local_sig.unlink(missing_ok=True)

        pkg_key = f"{category}/{pkg_file}"
        remote_pkg_url = f"{self.mirror_url}/{category}/{encoded_pkg}"
        if (
            pkg_key not in self.invalid_remote_pkgs
            and _http_head_ok(remote_pkg_url, self.ssl_ctx)
            and _http_head_ok(f"{remote_pkg_url}.sig", self.ssl_ctx)
        ):
            cache_pkg = pathlib.Path(f"/var/cache/pkgmk/packages/{pkg_file}")
            cache_sig = pathlib.Path(f"/var/cache/pkgmk/packages/{pkg_file}.sig")
            try:
                if not (cache_pkg.is_file() and cache_sig.is_file()):
                    _download_file(remote_pkg_url, cache_pkg, self.ssl_ctx)
                    _download_file(f"{remote_pkg_url}.sig", cache_sig, self.ssl_ctx, timeout=30.0)
                subprocess.run(
                    ["signify", "-p", "/etc/pkg-get/pkg-get.pub", "-V", "-q", "-m", str(cache_pkg), "-x", str(cache_sig)],
                    check=True,
                )
            except Exception:
                print(
                    f"==> [{mode_label}:WARN] {category}/{pkg_file} on {self.mirror_url} failed signature verification; rebuilding...",
                    flush=True,
                )
                cache_pkg.unlink(missing_ok=True)
                cache_sig.unlink(missing_ok=True)
                self.invalid_remote_pkgs.add(pkg_key)
                return False
            print(f"==> [{mode_label}:SKIP] {category}/{pkg_file} already published on {self.mirror_url}", flush=True)
            if install_if_skipped and not _prt_get_isinst(name):
                subprocess.run(["pkgadd", str(cache_pkg)], check=True)
            return True

        if allow_any_version:
            repo_cat = pathlib.Path(f"/repo/{category}")
            if repo_cat.is_dir():
                local_cands = [
                    p.name
                    for p in repo_cat.glob(f"{name}#*.pkg.tar.gz")
                    if p.is_file() and (repo_cat / f"{p.name}.sig").is_file()
                ]
                if local_cands:
                    best_local = _pick_newest_pkg_filename(local_cands)
                    best_pkg = repo_cat / best_local
                    best_sig = repo_cat / f"{best_local}.sig"
                    if (
                        subprocess.run(
                            ["signify", "-p", "/etc/pkg-get/pkg-get.pub", "-V", "-q", "-m", str(best_pkg), "-x", str(best_sig)],
                            check=False,
                        ).returncode
                        == 0
                    ):
                        print(f"==> [{mode_label}:DEP] Installing local pre-built dependency {category}/{best_local}", flush=True)
                        if not _prt_get_isinst(name):
                            subprocess.run(["pkgadd", str(best_pkg)], check=True)
                        return True

            remote_encoded = _find_matching_pkg_in_html(
                f"{self.mirror_url}/{category}/index.html",
                name,
                self.ssl_ctx,
            )
            if remote_encoded:
                remote_fname = urllib.parse.unquote(remote_encoded)
                if not _prt_get_isinst(name):
                    cache_pkg = pathlib.Path(f"/var/cache/pkgmk/packages/{remote_fname}")
                    cache_sig = pathlib.Path(f"/var/cache/pkgmk/packages/{remote_fname}.sig")
                    try:
                        _download_file(f"{self.mirror_url}/{category}/{remote_encoded}", cache_pkg, self.ssl_ctx)
                        _download_file(f"{self.mirror_url}/{category}/{remote_encoded}.sig", cache_sig, self.ssl_ctx, timeout=30.0)
                        subprocess.run(
                            ["signify", "-p", "/etc/pkg-get/pkg-get.pub", "-V", "-q", "-m", str(cache_pkg), "-x", str(cache_sig)],
                            check=True,
                        )
                        print(f"==> [{mode_label}:DEP] Installing mirror pre-built dependency {category}/{remote_fname}", flush=True)
                        subprocess.run(["pkgadd", str(cache_pkg)], check=True)
                        return True
                    except Exception:
                        print(
                            f"==> [{mode_label}:WARN] Mirror dependency {category}/{remote_fname} failed signature verification; falling back...",
                            flush=True,
                        )
                        cache_pkg.unlink(missing_ok=True)
                        cache_sig.unlink(missing_ok=True)
                else:
                    print(f"==> [{mode_label}:DEP] Installing mirror pre-built dependency {category}/{remote_fname}", flush=True)
                    return True

            cat_order = [category] + [c for c in CATEGORIES if c != category]
            for up_base in _upstream_mirrors(self.arch, self.distr):
                for up_cat in cat_order:
                    up_encoded = _find_matching_pkg_in_html(f"{up_base}/{up_cat}/", name, self.ssl_ctx)
                    if up_encoded:
                        up_fname = urllib.parse.unquote(up_encoded)
                        print(f"==> [{mode_label}:DEP] Fetching upstream pre-built dependency {up_cat}/{up_fname}", flush=True)
                        cache_pkg = pathlib.Path(f"/var/cache/pkgmk/packages/{up_fname}")
                        cache_sig = pathlib.Path(f"/var/cache/pkgmk/packages/{up_fname}.upstream.sig")
                        try:
                            _download_file(f"{up_base}/{up_cat}/{up_encoded}", cache_pkg, self.ssl_ctx)
                            _download_file(f"{up_base}/{up_cat}/{up_encoded}.sig", cache_sig, self.ssl_ctx, timeout=30.0)
                            subprocess.run(
                                ["signify", "-p", str(UPSTREAM_PUB_PATH), "-V", "-q", "-m", str(cache_pkg), "-x", str(cache_sig)],
                                check=True,
                            )
                        except Exception:
                            print(
                                f"==> [{mode_label}:WARN] Failed fetching/verifying {up_cat}/{up_fname} from {up_base}; trying next...",
                                flush=True,
                            )
                            cache_pkg.unlink(missing_ok=True)
                            cache_sig.unlink(missing_ok=True)
                            continue
                        repo_cat.mkdir(parents=True, exist_ok=True)
                        dest_pkg = repo_cat / up_fname
                        dest_sig = repo_cat / f"{up_fname}.sig"
                        shutil.copy2(cache_pkg, dest_pkg)
                        subprocess.run(
                            ["signify", "-s", "/etc/pkg-get/pkg-get.sec", "-S", "-m", str(dest_pkg), "-x", str(dest_sig)],
                            check=True,
                        )
                        if not _prt_get_isinst(name):
                            subprocess.run(["pkgadd", str(cache_pkg)], check=True)
                        cache_sig.unlink(missing_ok=True)
                        return True

        return False

    def ensure_implicit_deps(self) -> None:
        if self._in_implicit_deps:
            return
        self._in_implicit_deps = True
        try:
            max_passes = 6
            seen_ports: set[str] = set()
            for _ in range(max_passes):
                missing_ports = _find_missing_implicit_ports(self.arch)
                if not missing_ports:
                    break
                added_any = False
                for impl_pkg in missing_ports:
                    if impl_pkg in seen_ports:
                        continue
                    seen_ports.add(impl_pkg)
                    sub_deps = _prt_get_depends_uninstalled(impl_pkg)
                    if sub_deps:
                        for sub_dep in sub_deps:
                            sub_path = _prt_get_path(sub_dep)
                            if sub_path is not None:
                                print(
                                    f"==> [BUILD:IMPLICIT-DEP] Installing transitive .pc/.so dependency {sub_dep} (via {impl_pkg})",
                                    flush=True,
                                )
                                self.build_single_port(sub_path, role="dep")
                                added_any = True
                    elif not _prt_get_isinst(impl_pkg):
                        impl_path = _prt_get_path(impl_pkg)
                        if impl_path is not None:
                            print(
                                f"==> [BUILD:IMPLICIT-DEP] Installing transitive .pc/.so dependency {impl_pkg}",
                                flush=True,
                            )
                            self.build_single_port(impl_path, role="dep")
                            added_any = True
                if not added_any:
                    break
        finally:
            self._in_implicit_deps = False

    def build_single_port(
        self,
        port_dir: pathlib.Path,
        role: str = "target",
        skip_check: bool = False,
    ) -> None:
        collection = port_dir.parent.name
        category = collection.split("-")[-1]

        name, version, release = _source_pkgfile_meta(port_dir)
        pkg_file = f"{name}#{version}-{release}.pkg.tar.gz"
        encoded_pkg = f"{name}%23{version}-{release}.pkg.tar.gz"
        repo_cat_dir = pathlib.Path(f"/repo/{category}")
        repo_cat_dir.mkdir(parents=True, exist_ok=True)

        if not skip_check:
            allow_any = role == "dep" and not collection.startswith("custom-")
            if self.check_existing(
                category,
                name,
                pkg_file,
                encoded_pkg,
                "BUILD",
                allow_any_version=allow_any,
                install_if_skipped=(role == "dep"),
            ):
                return

        if not self._in_implicit_deps:
            self.ensure_implicit_deps()
            name, version, release = _source_pkgfile_meta(port_dir)
            pkg_file = f"{name}#{version}-{release}.pkg.tar.gz"

        print(f"==> [BUILD] Compiling {collection}/{name} ({version}-{release})...", flush=True)
        sec_key = pathlib.Path("/etc/pkg-get/pkg-get.sec")
        cache_sources = [pathlib.Path("/var/cache/pkgmk/sources")]
        upstream_cands = [
            pathlib.Path(f"/usr/ports/irradium-{category}/{name}"),
            pathlib.Path(f"/usr/ports/{category}/{name}"),
        ]
        if collection.startswith("custom-") and sec_key.is_file():
            signify.sign_port_signatures(
                port_dir,
                sec_path=sec_key,
                cache_source_dirs=cache_sources,
                upstream_port_dirs=upstream_cands,
            )

        pre_install = port_dir / "pre-install"
        if pre_install.is_file():
            subprocess.run(["sh", "./pre-install"], cwd=str(port_dir), check=True)

        subprocess.run(["pkgmk", "-d", "-f"], cwd=str(port_dir), check=True)

        if collection.startswith("custom-") and sec_key.is_file():
            signify.sign_port_signatures(
                port_dir,
                sec_path=sec_key,
                cache_source_dirs=cache_sources,
                upstream_port_dirs=upstream_cands,
            )
            signify.update_collection_repo(port_dir.parent, ensure_ignore_file=True)

        built_archive = pathlib.Path(f"/var/cache/pkgmk/packages/{pkg_file}")
        if not _prt_get_isinst(name):
            subprocess.run(["pkgadd", str(built_archive)], check=True)
        else:
            subprocess.run(["pkgadd", "-u", str(built_archive)], check=True)

        dest_pkg = repo_cat_dir / pkg_file
        dest_sig = repo_cat_dir / f"{pkg_file}.sig"
        shutil.copy2(built_archive, dest_pkg)
        subprocess.run(
            ["signify", "-s", "/etc/pkg-get/pkg-get.sec", "-S", "-m", str(dest_pkg), "-x", str(dest_sig)],
            check=True,
        )
        subprocess.run(
            ["signify", "-p", "/etc/pkg-get/pkg-get.pub", "-V", "-q", "-m", str(dest_pkg), "-x", str(dest_sig)],
            check=True,
        )
        print(f"==> [BUILD] Built & signed: {category}/{pkg_file}", flush=True)


def _fix_repo_ownership() -> None:
    """Ensure all files/dirs created under /repo match the host mount directory's UID/GID."""
    repo_root = pathlib.Path("/repo")
    if not repo_root.is_dir():
        return
    try:
        st = repo_root.stat()
        uid, gid = st.st_uid, st.st_gid
    except OSError:
        return
    if uid == 0 and gid == 0:
        return
    for p in repo_root.rglob("*"):
        try:
            os.lchown(p, uid, gid)
        except OSError:
            pass


def run_in_container(raw_targets: list[str]) -> int:
    """Entry point for `python3 -m pkgtool _container-run ...` inside the builder container."""
    _setup_container_environment()

    arch = os.environ.get("ARCH", "riscv64")
    distr = os.environ.get("DISTR_VERSION", "3.8")
    skip_existing = os.environ.get("SKIP_EXISTING", "no") == "yes"
    mirror_url = os.environ.get("MIRROR_URL", f"https://irradium.blackhole.com.br/irradium/packages/{arch}/{distr}")
    ssl_ctx = _create_ssl_context()

    try:
        upstream_targets = [
            t.split(":", 1)[1].rstrip("/")
            for t in raw_targets
            if t.startswith("upstream:")
        ]
        if upstream_targets:
            rc = _sync_upstream_targets(
                targets=upstream_targets,
                arch=arch,
                distr=distr,
                skip_existing=skip_existing,
                mirror_url=mirror_url,
                ssl_ctx=ssl_ctx,
            )
            if rc != 0:
                return rc

        builder = ContainerBuilder(
            arch=arch,
            distr=distr,
            skip_existing=skip_existing,
            mirror_url=mirror_url,
            ssl_ctx=ssl_ctx,
        )

        for item in raw_targets:
            mode, _, rest = item.partition(":")
            if mode == "upstream":
                continue
            target = (rest if rest else item).rstrip("/")
            if not TARGET_NAME_RE.fullmatch(target):
                print(f"ERROR: Invalid package or port target '{target}'", file=sys.stderr)
                return 1

            if "/" in target:
                cand_usr = pathlib.Path(f"/usr/ports/{target}")
                cand_mnt = pathlib.Path(f"/mnt/ports/{target}")
                if (cand_usr / "Pkgfile").is_file():
                    port_path = cand_usr
                elif (cand_mnt / "Pkgfile").is_file():
                    port_path = cand_mnt
                else:
                    print(f"ERROR: Pkgfile not found for '{target}'", file=sys.stderr)
                    return 1
                pkg_name = port_path.name
            else:
                pkg_name = target
                resolved = _prt_get_path(pkg_name)
                if resolved is None:
                    print(f"ERROR: Package '{pkg_name}' not found in any configured port tree", file=sys.stderr)
                    return 1
                port_path = resolved

            if builder.check_target_already_built(port_path):
                continue

            dep_pkgs = _prt_get_depends_uninstalled(pkg_name)
            processed_target = False
            for dep_pkg in dep_pkgs:
                dep_path = _prt_get_path(dep_pkg)
                if dep_path is None:
                    continue
                if dep_pkg == pkg_name:
                    builder.build_single_port(dep_path, role="target", skip_check=True)
                    processed_target = True
                else:
                    builder.build_single_port(dep_path, role="dep")

            if not processed_target:
                builder.build_single_port(port_path, role="target", skip_check=True)

        return 0
    finally:
        _fix_repo_ownership()
