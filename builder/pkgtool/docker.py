"""Host-side Docker image, keygen, shell, and container build orchestration."""

from __future__ import annotations

import dataclasses
import os
import pathlib
import re
import shlex
import subprocess
import sys

PKGTOOL_DIR = pathlib.Path(__file__).resolve().parent
BUILDER_DIR = PKGTOOL_DIR.parent
ROOT_DIR = BUILDER_DIR.parent

SUPPORTED_ARCHES: dict[str, str] = {
    "riscv64": "linux/riscv64",
    "aarch64": "linux/arm64",
}


def load_dotenv(dotenv_path: pathlib.Path | None = None) -> None:
    """Load key=value pairs from .env into os.environ (without clobbering existing env vars)."""
    path = dotenv_path or (ROOT_DIR / ".env")
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, val_raw = line.split("=", 1)
        key = key.strip()
        if not key:
            continue
        try:
            tokens = shlex.split(val_raw, comments=True)
            val = tokens[0] if tokens else ""
        except ValueError:
            val = val_raw.strip().strip("'\"")
        os.environ.setdefault(key, val)


def detect_distr_version(root_dir: pathlib.Path = ROOT_DIR) -> str:
    env_ver = os.environ.get("DISTR_VERSION", "").strip()
    if env_ver:
        return env_ver
    res = subprocess.run(
        ["git", "-C", str(root_dir), "branch", "--show-current"],
        capture_output=True,
        text=True,
        check=False,
    )
    branch = res.stdout.strip() if res.returncode == 0 else ""
    if re.fullmatch(r"\d+\.\d+", branch):
        return branch
    return "3.8"


@dataclasses.dataclass
class BuildConfig:
    arch: str
    distr_version: str
    ports_root: pathlib.Path
    cache_dir: pathlib.Path
    repo_root: pathlib.Path
    keys_dir: pathlib.Path
    r2_bucket: str
    r2_endpoint: str
    mirror_domain: str

    @classmethod
    def from_env(cls, arch_override: str | None = None) -> BuildConfig:
        load_dotenv()
        arch = (arch_override or os.environ.get("ARCH", "riscv64")).strip()
        if arch not in SUPPORTED_ARCHES:
            raise ValueError(f"Unsupported architecture '{arch}' (expected riscv64 or aarch64)")
        distr = detect_distr_version()
        ports_root = pathlib.Path(os.environ.get("PORTS_ROOT", str(ROOT_DIR / "ports"))).resolve()
        if arch_override or "CACHE_DIR" not in os.environ:
            cache_dir = (ROOT_DIR / "cache" / arch).resolve()
        else:
            cache_dir = pathlib.Path(os.environ["CACHE_DIR"]).resolve()
        repo_root = pathlib.Path(os.environ.get("REPO_ROOT", str(ROOT_DIR / "repo"))).resolve()
        keys_dir = pathlib.Path(os.environ.get("KEYS_DIR", str(ROOT_DIR / "keys"))).resolve()
        r2_bucket = os.environ.get("R2_BUCKET", "irradium")
        r2_endpoint = os.environ.get("R2_ENDPOINT", "")
        mirror_domain = os.environ.get("MIRROR_DOMAIN", "https://pkg.irradium.com.br").rstrip("/")
        return cls(
            arch=arch,
            distr_version=distr,
            ports_root=ports_root,
            cache_dir=cache_dir,
            repo_root=repo_root,
            keys_dir=keys_dir,
            r2_bucket=r2_bucket,
            r2_endpoint=r2_endpoint,
            mirror_domain=mirror_domain,
        )

    @property
    def docker_platform(self) -> str:
        return SUPPORTED_ARCHES[self.arch]

    @property
    def image_name(self) -> str:
        return f"irradium-{self.arch}:{self.distr_version}"

    @property
    def repo_dir(self) -> pathlib.Path:
        return self.repo_root / "irradium" / "packages" / self.arch / self.distr_version


def ensure_binfmt(cfg: BuildConfig) -> None:
    res = subprocess.run(
        ["docker", "run", "--rm", "--platform", cfg.docker_platform, cfg.image_name, "/bin/true"],
        capture_output=True,
        check=False,
    )
    if res.returncode != 0:
        print(f"==> Registering {cfg.arch} binfmt_misc handler in Docker VM...", flush=True)
        subprocess.run(
            ["docker", "run", "--privileged", "--rm", "tonistiigi/binfmt", "--install", cfg.arch],
            check=True,
        )


def build_image(cfg: BuildConfig) -> int:
    print(f"==> Building Docker image {cfg.image_name} ({cfg.docker_platform})...", flush=True)
    res = subprocess.run(
        [
            "docker",
            "build",
            "--platform",
            cfg.docker_platform,
            "--build-arg",
            f"ARCH={cfg.arch}",
            "--build-arg",
            f"DISTR_VERSION={cfg.distr_version}",
            "-t",
            cfg.image_name,
            str(BUILDER_DIR),
        ],
        check=False,
    )
    if res.returncode != 0:
        return res.returncode
    ensure_binfmt(cfg)
    return 0


def ensure_image(cfg: BuildConfig) -> None:
    res = subprocess.run(
        ["docker", "image", "inspect", cfg.image_name],
        capture_output=True,
        check=False,
    )
    if res.returncode != 0:
        rc = build_image(cfg)
        if rc != 0:
            raise RuntimeError(f"Failed to build Docker image {cfg.image_name}")
    else:
        ensure_binfmt(cfg)


def ensure_keys(cfg: BuildConfig) -> None:
    cfg.keys_dir.mkdir(parents=True, exist_ok=True)
    sec_file = cfg.keys_dir / "pkg-get.sec"
    pub_file = cfg.keys_dir / "pkg-get.pub"

    secret_env = os.environ.get("SIGNIFY_SECRET_KEY", "").strip()
    if secret_env and not sec_file.is_file():
        sec_file.write_text(secret_env + "\n", encoding="utf-8")
        sec_file.chmod(0o600)

    if not sec_file.is_file() or not pub_file.is_file():
        print(f"==> Generating signify keypair in {cfg.keys_dir}...", flush=True)
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--platform",
                cfg.docker_platform,
                "-v",
                f"{cfg.keys_dir}:/keys",
                cfg.image_name,
                "signify",
                "-G",
                "-n",
                "-p",
                "/keys/pkg-get.pub",
                "-s",
                "/keys/pkg-get.sec",
            ],
            check=True,
        )
        print(f"==> Public key generated at {pub_file}:", flush=True)
        print(pub_file.read_text(encoding="utf-8"), end="", flush=True)


def sign_repo(cfg: BuildConfig) -> int:
    ensure_image(cfg)
    ensure_keys(cfg)
    cfg.repo_dir.mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            cfg.docker_platform,
            "-v",
            f"{cfg.repo_dir}:/repo",
            "-v",
            f"{cfg.keys_dir}:/etc/pkg-get",
            cfg.image_name,
            "pkg-get",
            "-s",
            "/repo",
        ],
        check=False,
    )
    if res.returncode == 0:
        print(f"==> Signed all packages under {cfg.repo_dir}", flush=True)
    return res.returncode


def open_shell(cfg: BuildConfig) -> int:
    ensure_image(cfg)
    (cfg.cache_dir / "sources").mkdir(parents=True, exist_ok=True)
    (cfg.cache_dir / "packages").mkdir(parents=True, exist_ok=True)
    cfg.repo_dir.mkdir(parents=True, exist_ok=True)
    cfg.keys_dir.mkdir(parents=True, exist_ok=True)

    shell_init = """
mkdir -p /usr/ports /etc/ports
if [[ -f /etc/pkg-get/pkg-get.pub ]]; then
    for c in core opt xorg xfce contrib; do
        cp /etc/pkg-get/pkg-get.pub "/etc/ports/custom-$c.pub"
    done
fi
for c in core opt xorg xfce contrib; do
    mkdir -p "/mnt/ports/custom/custom-$c"
    ln -sfn "/mnt/ports/custom/custom-$c" "/usr/ports/custom-$c"
    if [[ -d "/mnt/ports/irradium/irradium-$c" ]]; then
        ln -sfn "/mnt/ports/irradium/irradium-$c" "/usr/ports/irradium-$c"
    else
        mkdir -p "/usr/ports/irradium-$c"
    fi
done
for c in core opt xorg contrib; do
    if [[ -d "/mnt/ports/crux-$c" ]]; then
        ln -sfn "/mnt/ports/crux-$c" "/usr/ports/$c"
    else
        mkdir -p "/usr/ports/$c"
    fi
done
exec /bin/bash
"""
    os.execvp(
        "docker",
        [
            "docker",
            "run",
            "--rm",
            "-it",
            "--platform",
            cfg.docker_platform,
            "-v",
            f"{cfg.ports_root}:/mnt/ports",
            "-v",
            f"{cfg.cache_dir}:/var/cache/pkgmk",
            "-v",
            f"{cfg.repo_dir}:/repo",
            "-v",
            f"{cfg.keys_dir}:/etc/pkg-get",
            "-v",
            f"{BUILDER_DIR}:/mnt/builder:ro",
            cfg.image_name,
            "/bin/bash",
            "-c",
            shell_init,
        ],
    )
    return 0


def run_container_build(
    cfg: BuildConfig,
    targets: list[str],
    skip_existing: bool = False,
) -> int:
    ensure_image(cfg)
    ensure_keys(cfg)
    (cfg.cache_dir / "sources").mkdir(parents=True, exist_ok=True)
    (cfg.cache_dir / "packages").mkdir(parents=True, exist_ok=True)
    cfg.repo_dir.mkdir(parents=True, exist_ok=True)

    mirror_url = f"{cfg.mirror_domain}/irradium/packages/{cfg.arch}/{cfg.distr_version}"
    res = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--platform",
            cfg.docker_platform,
            "-e",
            f"SKIP_EXISTING={'yes' if skip_existing else 'no'}",
            "-e",
            f"MIRROR_URL={mirror_url}",
            "-e",
            f"ARCH={cfg.arch}",
            "-e",
            f"DISTR_VERSION={cfg.distr_version}",
            "-e",
            "PYTHONPATH=/mnt/builder",
            "-v",
            f"{cfg.ports_root}:/mnt/ports",
            "-v",
            f"{cfg.cache_dir}:/var/cache/pkgmk",
            "-v",
            f"{cfg.repo_dir}:/repo",
            "-v",
            f"{cfg.keys_dir}:/etc/pkg-get",
            "-v",
            f"{BUILDER_DIR}:/mnt/builder:ro",
            cfg.image_name,
            "python3",
            "-m",
            "pkgtool",
            "_container-run",
            *targets,
        ],
        check=False,
    )
    return res.returncode
