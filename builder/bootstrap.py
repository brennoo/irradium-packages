import concurrent.futures
import os
import re
import ssl
import subprocess
import urllib.parse
import urllib.request

# dl.irradium.org serves only its leaf certificate without the intermediate CA chain.
# Supplying the intermediate CA certificates (ZeroSSL ECC DV SSL CA 2 -> Sectigo Root E46
# cross-signed by USERTrust ECC Certification Authority) allows strict TLS verification
# against the system root CA store without disabling certificate validation.
MISSING_INTERMEDIATES_PEM = """
-----BEGIN CERTIFICATE-----
MIIDNTCCArugAwIBAgIRAMThxbsA8CePNHvk+F1j/MowCgYIKoZIzj0EAwMwXzEL
MAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDE2MDQGA1UEAxMt
U2VjdGlnbyBQdWJsaWMgU2VydmVyIEF1dGhlbnRpY2F0aW9uIFJvb3QgRTQ2MB4X
DTI1MDkyNDAwMDAwMFoXDTM1MDkyMzIzNTk1OVowRjELMAkGA1UEBhMCQVQxFTAT
BgNVBAoTDFplcm9TU0wgR21iSDEgMB4GA1UEAxMXWmVyb1NTTCBFQ0MgRFYgU1NM
IENBIDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATjn4qR1IOXAceCMsej8Qyr
4PrFw+PwjPm2vrAfijBj4u2C++Y3pZqpeLi1z05b2owKKJzQk1AtL+m1fEoFeDka
o4IBbzCCAWswHwYDVR0jBBgwFoAU0SLaTFnxS18mOKqd1u7rDcP7qWEwHQYDVR0O
BBYEFJRFn9pRR3HVc66sHasIchJtrXxiMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMB
Af8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBMGA1UdIAQMMAowCAYG
Z4EMAQIBMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly9jcmwuc2VjdGlnby5jb20v
U2VjdGlnb1B1YmxpY1NlcnZlckF1dGhlbnRpY2F0aW9uUm9vdEU0Ni5jcmwwgYQG
CCsGAQUFBwEBBHgwdjBPBggrBgEFBQcwAoZDaHR0cDovL2NydC5zZWN0aWdvLmNv
bS9TZWN0aWdvUHVibGljU2VydmVyQXV0aGVudGljYXRpb25Sb290RTQ2LnA3YzAj
BggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wCgYIKoZIzj0EAwMD
aAAwZQIwXKxxvuUkvPftBuaOFx73U3FxmFtKxP1Fd/+8Jq/ut2XgDrJ1vEUDdJb3
iSDXVe9AAjEA8iUwhrRHdZrIWqfgGmDMBbuXRZ4GoQbLpwxgcPhKo3OZR7SecTp4
juWAOpuawM2n
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDRjCCAsugAwIBAgIQGp6v7G3o4ZtcGTFBto2Q3TAKBggqhkjOPQQDAzCBiDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNl
eSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMT
JVVTRVJUcnVzdCBFQ0MgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIy
MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBfMQswCQYDVQQGEwJHQjEYMBYGA1UEChMP
U2VjdGlnbyBMaW1pdGVkMTYwNAYDVQQDEy1TZWN0aWdvIFB1YmxpYyBTZXJ2ZXIg
QXV0aGVudGljYXRpb24gUm9vdCBFNDYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR2
+pmpbiDt+dd34wc7qNs9Xzjoq1WmVk/WSOrsfy2qw7LFeeyZYX8QeccCWvkEN/U0
NSt3zn8gj1KjAIns1aeibVvjS5KToID1AZTc8GgHHs3u/iVStSBDHBv+6xnOQ6Oj
ggEgMIIBHDAfBgNVHSMEGDAWgBQ64QmG1M8ZwpZ2dEl23OA1xmNjmjAdBgNVHQ4E
FgQU0SLaTFnxS18mOKqd1u7rDcP7qWEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBEGA1UdIAQK
MAgwBgYEVR0gADBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwOi8vY3JsLnVzZXJ0cnVz
dC5jb20vVVNFUlRydXN0RUNDQ2VydGlmaWNhdGlvbkF1dGhvcml0eS5jcmwwNQYI
KwYBBQUHAQEEKTAnMCUGCCsGAQUFBzABhhlodHRwOi8vb2NzcC51c2VydHJ1c3Qu
Y29tMAoGCCqGSM49BAMDA2kAMGYCMQCMCyBit99vX2ba6xEkDe+YO7vC0twjbkv9
PKpqGGuZ61JZryjFsp+DFpEclCVy4noCMQCwvZDXD/m2Ko1HA5Bkmz7YQOFAiNDD
49IWa2wdT7R3DtODaSXH/BiXv8fwB9su4tU=
-----END CERTIFICATE-----
"""

# Official Irradium pkg-get signify public key (from https://gitlab.com/sndwvs/pkg-get)
IRRADIUM_PKG_GET_PUB = """untrusted comment: pkg-get public key
RWTuJkODJcOmD4iSbIIUzRt+qT73ua9l6E916KuyYLp4qc5MM42EMIp0
"""
UPSTREAM_PUBKEY_PATH = "/tmp/irradium-pkg-get.pub"

SSL_CTX = ssl.create_default_context()
SSL_CTX.load_verify_locations(cadata=MISSING_INTERMEDIATES_PEM)

ARCH = os.environ.get("ARCH", "riscv64")
DISTR_VERSION = os.environ.get("DISTR_VERSION", "3.8")
UPSTREAM_MIRRORS = [
    f"https://mirror.accum.se/mirror/irradium.org/packages/{ARCH}/{DISTR_VERSION}",
    f"https://ftp.cc.uoc.gr/mirrors/linux/irradium/packages/{ARCH}/{DISTR_VERSION}",
    f"https://dl.irradium.org/irradium/packages/{ARCH}/{DISTR_VERSION}",
]


def select_base_url():
    custom = os.environ.get("UPSTREAM_URL")
    candidates = [custom.rstrip("/")] if custom else UPSTREAM_MIRRORS
    last_err = None
    for candidate in candidates:
        try:
            url = f"{candidate}/core/"
            with urllib.request.urlopen(url, timeout=10, context=SSL_CTX) as r:
                if r.status == 200:
                    return candidate
        except Exception as e:
            print(f"Mirror {candidate} unavailable ({e}), trying next...")
            last_err = e
    raise RuntimeError(f"All Irradium upstream mirrors failed; last error: {last_err}")

CORE_WANTED = {
    "filesystem", "iana-etc", "tzdata", "glibc", "gcc", "binutils", "make",
    "bash", "dash", "coreutils", "util-linux", "sed", "grep", "gawk",
    "findutils", "diffutils", "patch", "file", "tar", "gzip", "bzip2", "xz",
    "zstd", "zlib", "lzlib", "lzo", "acl", "attr", "libcap", "libcap-ng",
    "libxcrypt", "ncurses", "readline", "libedit", "libgmp", "libmpfr",
    "libmpc", "libpcre", "libpcre2", "openssl", "ca-certificates",
    "libnghttp2", "curl", "libarchive", "expat", "pkgconf", "pkgutils",
    "prt-get", "ports", "signify", "httpup", "m4", "autoconf", "automake",
    "libtool", "bison", "flex", "gperf", "bc", "ed", "cpio", "which", "time",
    "procps", "psmisc", "shadow", "linux-pam", "libmd", "libbsd", "libffi",
    "elfutils", "gettext", "perl", "gdbm", "db", "libnsl", "libtirpc", "eudev",
    "e2fsprogs", "kmod", "less", "jansson", "ninja", "rsync", "cmake",
    "jsoncpp", "libuv", "rhash", "nasm", "groff", "libpipeline", "man-db",
    "python3", "python3-setuptools", "meson", "sqlite3", "mpdecimal"
}

CONTRIB_WANTED = {
    "lz4"
}

OPT_WANTED = {
    "pkg-get", "texinfo"
}


def fetch_listing(base_url, repo, wanted):
    url = f"{base_url}/{repo}/"
    req = urllib.request.urlopen(url, timeout=30, context=SSL_CTX)
    html = req.read().decode("utf-8", errors="replace")
    found = {}
    for m in re.finditer(r'href="([^"]+\.pkg\.tar\.gz)"', html):
        href = m.group(1)
        fname = urllib.parse.unquote(href)
        pkgname = fname.split("#")[0]
        if pkgname in wanted:
            found[pkgname] = (fname, f"{url}{href}")
    missing = wanted - set(found.keys())
    if missing:
        raise RuntimeError(f"Missing packages in {repo} ({url}): {missing}")
    return found


def download_and_verify_pkg(item):
    pkgname, (fname, url) = item
    dest = f"/tmp/pkgs/{fname}"
    sig_dest = f"{dest}.sig"
    sig_url = f"{url}.sig"

    if not os.path.exists(dest):
        with urllib.request.urlopen(url, timeout=60, context=SSL_CTX) as r, open(dest, "wb") as f:
            while chunk := r.read(65536):
                f.write(chunk)

    if not os.path.exists(sig_dest):
        with urllib.request.urlopen(sig_url, timeout=30, context=SSL_CTX) as r, open(sig_dest, "wb") as f:
            f.write(r.read())

    # Verify Ed25519 signify signature before trusting the package archive
    subprocess.run(
        ["signify", "-V", "-q", "-p", UPSTREAM_PUBKEY_PATH, "-m", dest, "-x", sig_dest],
        check=True,
    )
    return pkgname, fname, dest


def main():
    os.makedirs("/tmp/pkgs", exist_ok=True)
    os.makedirs("/rootfs", exist_ok=True)

    with open(UPSTREAM_PUBKEY_PATH, "w", encoding="utf-8") as f:
        f.write(IRRADIUM_PKG_GET_PUB)

    base_url = select_base_url()
    print(f"Bootstrapping Irradium {DISTR_VERSION} ({ARCH}) from {base_url} (TLS + signify verified)...")
    pkgs = {}
    pkgs.update(fetch_listing(base_url, "core", CORE_WANTED))
    pkgs.update(fetch_listing(base_url, "contrib", CONTRIB_WANTED))
    pkgs.update(fetch_listing(base_url, "opt", OPT_WANTED))

    print(f"Downloading and verifying {len(pkgs)} packages...")
    downloaded = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for pkgname, fname, dest in ex.map(download_and_verify_pkg, pkgs.items()):
            downloaded[pkgname] = (fname, dest)

    # Extract filesystem first so /lib64 -> lib and /usr/lib64 -> lib symlinks exist
    order = ["filesystem"] + sorted(k for k in downloaded if k != "filesystem")
    db_lines = []

    for pkgname in order:
        fname, path = downloaded[pkgname]
        ver = fname.split("#", 1)[1].rsplit(".pkg.tar.", 1)[0]
        out = subprocess.check_output(["bsdtar", "-tf", path], text=True)
        files = []
        for line in out.splitlines():
            clean = re.sub(r"^\./", "", line)
            if clean:
                files.append(clean)
        db_lines.append(f"{pkgname}\n{ver}\n" + "\n".join(files) + "\n")

        subprocess.check_call(["bsdtar", "-xpf", path, "-C", "/rootfs"])

    os.makedirs("/rootfs/var/lib/pkg", exist_ok=True)
    with open("/rootfs/var/lib/pkg/db", "w", encoding="utf-8") as f:
        f.write("\n".join(db_lines))
    open("/rootfs/var/lib/pkg/prt-get.locker", "a").close()

    # Install intermediate CA certs into /rootfs so in-container tools can also verify ZeroSSL chains
    os.makedirs("/rootfs/usr/local/share/ca-certificates", exist_ok=True)
    with open("/rootfs/usr/local/share/ca-certificates/zerossl-sectigo-intermediates.crt", "w", encoding="utf-8") as f:
        f.write(MISSING_INTERMEDIATES_PEM.strip() + "\n")
    for bundle in ("/rootfs/etc/ssl/cert.pem", "/rootfs/etc/ssl/certs/ca-certificates.crt"):
        if os.path.exists(bundle):
            with open(bundle, "a", encoding="utf-8") as f:
                f.write("\n" + MISSING_INTERMEDIATES_PEM.strip() + "\n")

    # Configure /etc/pkgmk.conf for shared cache directories
    os.makedirs("/rootfs/var/cache/pkgmk/sources", exist_ok=True)
    os.makedirs("/rootfs/var/cache/pkgmk/packages", exist_ok=True)
    os.makedirs("/rootfs/tmp/pkgmk-work", exist_ok=True)
    with open("/rootfs/etc/pkgmk.conf", "a", encoding="utf-8") as f:
        f.write("\nPKGMK_SOURCE_DIR=\"/var/cache/pkgmk/sources\"\n")
        f.write("PKGMK_PACKAGE_DIR=\"/var/cache/pkgmk/packages\"\n")
        f.write("PKGMK_WORK_DIR=\"/tmp/pkgmk-work/$name\"\n")

    # Configure /etc/prt-get.conf with priority hierarchy:
    # 1. custom-* (local overrides)
    # 2. irradium-* (Irradium multi-arch ports)
    # 3. core, opt, xorg, contrib (upstream CRUX ports)
    prt_conf = """###
### /etc/prt-get.conf: prt-get(8) configuration
###

prtdir /usr/ports/custom-core
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

logfile  /var/log/pkgbuild/%n.log
runscripts yes
"""
    with open("/rootfs/etc/prt-get.conf", "w", encoding="utf-8") as f:
        f.write(prt_conf)


if __name__ == "__main__":
    main()
