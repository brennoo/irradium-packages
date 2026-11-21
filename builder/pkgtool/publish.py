"""Static HTML directory index generation and R2/S3 mirror publishing."""

from __future__ import annotations

from collections import defaultdict
import html
import os
import pathlib
import subprocess
import sys
import tempfile
import typing
import urllib.parse


def human_size(num_bytes: int) -> str:
    val = float(num_bytes)
    for unit in ("B", "K", "M", "G"):
        if val < 1024.0 or unit == "G":
            return f"{int(val)}" if unit == "B" else f"{val:.1f}{unit}"
        val /= 1024.0
    return f"{num_bytes}"


def render_dir_index(
    rel_dir: str,
    subdirs: list[str],
    files: list[tuple[str, str, int]],
    is_root: bool = False,
    all_files: list[tuple[str, str, int]] | None = None,
) -> str:
    title_path = "/" + rel_dir.strip("/")
    if title_path != "/":
        title_path += "/"

    rows: list[str] = []
    if not is_root:
        parent = "../index.html"
        rows.append(f'<tr><td><a href="{parent}">../</a></td><td>-</td><td align="right">-</td></tr>')

    for d in sorted(subdirs):
        href = urllib.parse.quote(d) + "/index.html"
        rows.append(f'<tr><td><a href="{href}">{html.escape(d)}/</a></td><td>-</td><td align="right">-</td></tr>')

    for name, mtime, size in sorted(files, key=lambda x: x[0]):
        href = urllib.parse.quote(name)
        rows.append(
            f'<tr><td><a href="{href}">{html.escape(name)}</a></td>'
            f'<td>{html.escape(mtime)}</td>'
            f'<td align="right">{human_size(size)}</td></tr>'
        )

    all_pkg_section = ""
    if is_root and all_files:
        pkg_rows: list[str] = []
        for path, mtime, size in sorted(all_files, key=lambda x: x[0]):
            if path.endswith("/index.html") or path == "index.html":
                continue
            parts = path.split("/")
            href = "/".join(urllib.parse.quote(p) for p in parts)
            pkg_rows.append(
                f'<tr><td><a href="/{href}">{html.escape(path)}</a></td>'
                f'<td>{html.escape(mtime)}</td>'
                f'<td align="right">{human_size(size)}</td></tr>'
            )
        if pkg_rows:
            all_pkg_section = f"""
<h2>All Published Files</h2>
<table>
  <thead>
    <tr><th align="left">Path</th><th align="left">Last modified</th><th align="right">Size</th></tr>
  </thead>
  <tbody>
    {"".join(pkg_rows)}
  </tbody>
</table>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Index of {html.escape(title_path)}</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; margin: 2rem; color: #e6edf3; background: #0d1117; }}
    h1, h2 {{ font-size: 1.25rem; margin-bottom: 1rem; font-weight: 600; }}
    h2 {{ margin-top: 2.5rem; font-size: 1.05rem; color: #8b949e; }}
    a {{ color: #58a6ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 960px; }}
    th, td {{ padding: 0.35rem 0.75rem; border-bottom: 1px solid #21262d; font-size: 0.9rem; }}
    th {{ color: #8b949e; border-bottom: 1px solid #30363d; }}
    .meta {{ margin-bottom: 1.5rem; color: #8b949e; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <h1>Index of {html.escape(title_path)}</h1>
  <div class="meta">Irradium Binary Package Mirror &middot; <a href="https://github.com/brennoo/irradium-packages">github.com/brennoo/irradium-packages</a></div>
  <table>
    <thead>
      <tr><th align="left">Name</th><th align="left">Last modified</th><th align="right">Size</th></tr>
    </thead>
    <tbody>
      {"".join(rows)}
    </tbody>
  </table>
  {all_pkg_section}
</body>
</html>
"""


def generate_indexes_from_s3_lines(lines: typing.Iterable[str], out_root: str | pathlib.Path) -> None:
    """Parse `aws s3 ls --recursive` lines and write HTML directory indexes under out_root."""
    out_root_str = str(out_root)
    dir_subdirs: dict[str, set[str]] = defaultdict(set)
    dir_files: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    all_files: list[tuple[str, str, int]] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        # aws s3 ls format: YYYY-MM-DD HH:MM:SS <size> <key>
        parts = line.split(None, 3)
        if len(parts) != 4 or parts[2] == "PRE":
            continue
        date_s, time_s, size_s, key = parts
        if key.endswith("/index.html") or key == "index.html" or key.endswith("pkg-get.pub"):
            continue
        try:
            size = int(size_s)
        except ValueError:
            continue
        mtime = f"{date_s} {time_s}"
        all_files.append((key, mtime, size))

        segments = key.strip("/").split("/")
        for i in range(len(segments) - 1):
            parent = "/".join(segments[:i])
            child = segments[i]
            dir_subdirs[parent].add(child)

        parent_dir = "/".join(segments[:-1])
        fname = segments[-1]
        dir_files[parent_dir].append((fname, mtime, size))

    all_dirs = set(dir_subdirs.keys()) | set(dir_files.keys()) | {""}
    for d in sorted(all_dirs):
        target_dir = os.path.join(out_root_str, d) if d else out_root_str
        os.makedirs(target_dir, exist_ok=True)
        index_path = os.path.join(target_dir, "index.html")
        content = render_dir_index(
            d,
            sorted(dir_subdirs.get(d, set())),
            dir_files.get(d, []),
            is_root=(d == ""),
            all_files=all_files if d == "" else None,
        )
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(content)


def publish_repo(
    repo_root: pathlib.Path,
    r2_bucket: str,
    r2_endpoint: str,
    mirror_domain: str,
) -> int:
    """Sync local repo/irradium/packages/ to R2 and regenerate/upload HTML directory indexes."""
    if not r2_endpoint:
        print("ERROR: R2_ENDPOINT is not set (configure it in .env or environment)", file=sys.stderr)
        return 1

    pkgs_dir = repo_root / "irradium" / "packages"
    pkgs_dir.mkdir(parents=True, exist_ok=True)
    # Signify .sig files are a fixed 155 bytes; touch them before syncing so
    # `aws s3 sync` never skips a .sig whose local mtime is older than R2's
    # while uploading a differently-sized .pkg.tar.gz.
    for sig_path in pkgs_dir.rglob("*.sig"):
        if sig_path.is_file():
            sig_path.touch()
    remote_pkgs = f"s3://{r2_bucket}/irradium/packages/"
    print(f"==> Syncing {pkgs_dir}/ to {remote_pkgs}...", flush=True)

    sync_cmd = [
        "aws",
        "s3",
        "sync",
        f"{pkgs_dir}/",
        remote_pkgs,
        "--endpoint-url",
        r2_endpoint,
        "--region",
        "auto",
    ]
    sync_status = 0
    res = subprocess.run(sync_cmd, check=False)
    if res.returncode != 0:
        print("==> Retrying aws s3 sync after transient upload failure...", file=sys.stderr, flush=True)
        res_retry = subprocess.run(sync_cmd, check=False)
        if res_retry.returncode != 0:
            sync_status = res_retry.returncode

    print("==> Generating HTML index listings...", flush=True)
    with tempfile.TemporaryDirectory(prefix="irradium-index-") as index_tmp:
        ls_proc = subprocess.run(
            [
                "aws",
                "s3",
                "ls",
                remote_pkgs,
                "--recursive",
                "--endpoint-url",
                r2_endpoint,
                "--region",
                "auto",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        generate_indexes_from_s3_lines(ls_proc.stdout.splitlines(), index_tmp)
        subprocess.run(
            [
                "aws",
                "s3",
                "sync",
                f"{index_tmp}/",
                f"s3://{r2_bucket}/",
                "--endpoint-url",
                r2_endpoint,
                "--region",
                "auto",
                "--content-type",
                "text/html; charset=utf-8",
                "--cache-control",
                "no-cache",
            ],
            check=True,
        )

    if sync_status != 0:
        return sync_status

    print(f"==> Published packages and index to {mirror_domain.rstrip('/')}/", flush=True)
    return 0


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output-root-dir>", file=sys.stderr)
        sys.exit(1)
    generate_indexes_from_s3_lines(sys.stdin, sys.argv[1])


if __name__ == "__main__":
    main()
