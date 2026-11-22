"""R2/S3 binary package mirror publishing."""

from __future__ import annotations

import concurrent.futures
import datetime
import pathlib
import subprocess
import sys
import time


def _list_remote_objects(
    remote_pkgs: str,
    r2_endpoint: str,
) -> dict[str, tuple[float, int]]:
    """Run `aws s3 ls --recursive` and return `{s3_key: (mtime_epoch, size)}`."""
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
    remote_objects: dict[str, tuple[float, int]] = {}
    for raw_line in ls_proc.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(None, 3)
        if len(parts) != 4 or parts[2] == "PRE":
            continue
        date_s, time_s, size_s, key = parts
        try:
            size = int(size_s)
            dt = datetime.datetime.strptime(f"{date_s} {time_s}", "%Y-%m-%d %H:%M:%S")
            mtime_epoch = dt.timestamp()
        except ValueError:
            continue
        remote_objects[key.strip("/")] = (mtime_epoch, size)
    return remote_objects


def _upload_one_file(
    local_path: pathlib.Path,
    s3_uri: str,
    r2_endpoint: str,
    max_attempts: int = 3,
) -> None:
    cmd = [
        "aws",
        "s3",
        "cp",
        str(local_path),
        s3_uri,
        "--endpoint-url",
        r2_endpoint,
        "--region",
        "auto",
        "--cli-read-timeout",
        "300",
        "--cli-connect-timeout",
        "60",
        "--no-progress",
    ]
    last_rc = 1
    for attempt in range(1, max_attempts + 1):
        res = subprocess.run(cmd, check=False)
        if res.returncode == 0:
            return
        last_rc = res.returncode
        if attempt < max_attempts:
            print(
                f"==> [PUBLISH:RETRY] Upload attempt {attempt}/{max_attempts} failed for {local_path.name}; retrying...",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(2 * attempt)
    raise subprocess.CalledProcessError(last_rc, cmd)


def publish_repo(
    repo_root: pathlib.Path,
    r2_bucket: str,
    r2_endpoint: str,
    mirror_domain: str,
) -> int:
    """Sync local repo/irradium/packages/ to R2."""
    if not r2_endpoint:
        print("ERROR: R2_ENDPOINT is not set (configure it in .env or environment)", file=sys.stderr)
        return 1

    # Use classic s3transfer client instead of CRT so Cloudflare R2 multipart
    # finalization does not fail with AWS_ERROR_HTTP_RESPONSE_FIRST_BYTE_TIMEOUT.
    subprocess.run(
        ["aws", "configure", "set", "default.s3.preferred_transfer_client", "classic"],
        check=False,
    )

    pkgs_dir = repo_root / "irradium" / "packages"
    pkgs_dir.mkdir(parents=True, exist_ok=True)
    remote_pkgs = f"s3://{r2_bucket}/irradium/packages/"
    print(f"==> Inspecting remote objects on {remote_pkgs}...", flush=True)
    remote_objects = _list_remote_objects(remote_pkgs, r2_endpoint)

    # Note: Cloudflare R2's ListObjectsV2 returns `<pkg>.pkg.tar.gz.sig` before
    # `<pkg>.pkg.tar.gz`, which breaks `aws s3 sync`'s merge-join Comparator into
    # thinking every `.pkg.tar.gz` does not exist on the destination. Comparing
    # against `remote_objects` in Python avoids that bug and ensures `.sig` is
    # always uploaded whenever its companion `.pkg.tar.gz` is uploaded.
    to_upload: list[tuple[pathlib.Path, str]] = []
    handled_sigs: set[pathlib.Path] = set()

    for pkg_path in sorted(pkgs_dir.rglob("*.pkg.tar.gz")):
        if not pkg_path.is_file():
            continue
        rel_pkg = pkg_path.relative_to(repo_root).as_posix()
        pkg_stat = pkg_path.stat()
        rem_pkg = remote_objects.get(rel_pkg)
        need_pkg = (
            rem_pkg is None
            or rem_pkg[1] != pkg_stat.st_size
            or int(pkg_stat.st_mtime) > int(rem_pkg[0])
        )
        if need_pkg:
            to_upload.append((pkg_path, f"s3://{r2_bucket}/{rel_pkg}"))

        sig_path = pkg_path.with_name(pkg_path.name + ".sig")
        if sig_path.is_file():
            handled_sigs.add(sig_path)
            rel_sig = sig_path.relative_to(repo_root).as_posix()
            sig_stat = sig_path.stat()
            rem_sig = remote_objects.get(rel_sig)
            need_sig = (
                need_pkg
                or rem_sig is None
                or rem_sig[1] != sig_stat.st_size
                or int(sig_stat.st_mtime) > int(rem_sig[0])
            )
            if need_sig:
                to_upload.append((sig_path, f"s3://{r2_bucket}/{rel_sig}"))

    for sig_path in sorted(pkgs_dir.rglob("*.sig")):
        if sig_path in handled_sigs or not sig_path.is_file():
            continue
        rel_sig = sig_path.relative_to(repo_root).as_posix()
        sig_stat = sig_path.stat()
        rem_sig = remote_objects.get(rel_sig)
        if (
            rem_sig is None
            or rem_sig[1] != sig_stat.st_size
            or int(sig_stat.st_mtime) > int(rem_sig[0])
        ):
            to_upload.append((sig_path, f"s3://{r2_bucket}/{rel_sig}"))

    if to_upload:
        print(f"==> Uploading {len(to_upload)} new/updated file(s) to {remote_pkgs}...", flush=True)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
                futures = [
                    ex.submit(_upload_one_file, local_p, s3_uri, r2_endpoint)
                    for local_p, s3_uri in to_upload
                ]
                for fut in concurrent.futures.as_completed(futures):
                    fut.result()
        except subprocess.CalledProcessError as exc:
            return exc.returncode or 1
    else:
        print(f"==> All local packages in {pkgs_dir}/ are already up to date on {remote_pkgs}", flush=True)

    print(f"==> Published packages to {mirror_domain.rstrip('/')}/", flush=True)
    return 0
