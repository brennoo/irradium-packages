# Irradium Packages

[![Build & Publish](https://github.com/brennoo/irradium-packages/actions/workflows/build-packages.yml/badge.svg?branch=3.8)](https://github.com/brennoo/irradium-packages/actions/workflows/build-packages.yml)
[![Sync Upstream](https://github.com/brennoo/irradium-packages/actions/workflows/sync-submodules.yml/badge.svg?branch=3.8)](https://github.com/brennoo/irradium-packages/actions/workflows/sync-submodules.yml)
[![Vulnerability Scan](https://github.com/brennoo/irradium-packages/actions/workflows/vuln-scan.yml/badge.svg?branch=3.8)](https://github.com/brennoo/irradium-packages/actions/workflows/vuln-scan.yml)

This repository aims to provide low-CVE packages, backporting security patches and [VEXing](builder/vex) triaged vulnerabilities.

[![Critical](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrennoo%2Firradium-packages%2Fbadges%2Fvuln-critical.json)](https://github.com/brennoo/irradium-packages/actions/workflows/vuln-scan.yml)
[![High](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrennoo%2Firradium-packages%2Fbadges%2Fvuln-high.json)](https://github.com/brennoo/irradium-packages/actions/workflows/vuln-scan.yml)
[![Medium](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrennoo%2Firradium-packages%2Fbadges%2Fvuln-medium.json)](https://github.com/brennoo/irradium-packages/actions/workflows/vuln-scan.yml)
[![Low](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fbrennoo%2Firradium-packages%2Fbadges%2Fvuln-low.json)](https://github.com/brennoo/irradium-packages/actions/workflows/vuln-scan.yml)

Pre-built binary packages for **[Irradium](https://irradium.org/) 3.8** - focused on `riscv64`.

## Setup on Your Device

Run the bootstrap script as `root` on your **Irradium 3.8** system to install the signing key, configure the binary mirror, and enable/sync the `custom-*` port collections:

```bash
curl -fsSL https://raw.githubusercontent.com/brennoo/irradium-packages/3.8/setup.sh | sh
```

<details>
<summary>Manual step-by-step setup</summary>

### 1. Install the Public Signing Key

Fetch the public `signify` verification key directly from GitHub:

```bash
curl -fsSL https://raw.githubusercontent.com/brennoo/irradium-packages/3.8/keys/pkg-get.pub \
  -o /etc/pkg-get/pkg-get.pub
```

### 2. Configure the Package Mirror

Set the binary mirror in `/etc/pkg-get/mirrors` (`pkg-get` automatically replaces `ARCH` with your system's `uname -m` architecture and filters by your `irradium` release version):

```bash
sed -i 's|^https://|# https://|' /etc/pkg-get/mirrors
echo "https://irradium.blackhole.com.br/irradium/packages/ARCH/3.8" >> /etc/pkg-get/mirrors
```

### 3. Enable Custom Port Collections (`custom-*`)

Register and sync the `custom-*` port collections so `prt-get` and `pkg-get` can discover custom ports (like `notqmail`) and security-patched overrides:

```bash
for col in custom-core custom-opt custom-xfce custom-contrib; do
  cp /etc/pkg-get/pkg-get.pub /etc/ports/${col}.pub
  cat > /etc/ports/${col}.httpup << EOF
ROOT_DIR=/usr/ports/${col}
URL=https://raw.githubusercontent.com/brennoo/irradium-packages/3.8/ports/custom/${col}/
EOF
done

sed -i '1i prtdir /usr/ports/custom-core\nprtdir /usr/ports/custom-opt\nprtdir /usr/ports/custom-xorg\nprtdir /usr/ports/custom-xfce\nprtdir /usr/ports/custom-contrib' /etc/prt-get.conf
ports -u custom-core custom-opt custom-xfce custom-contrib
```

</details>

### Install & Update Packages

`pkg-get` resolves available package versions and dependencies from your local `/usr/ports` tree via `prt-get`:

```bash
# Refresh the list of available packages and versions
ports -u

# Upgrade installed packages to newer versions in /usr/ports
pkg-get -u

# Install a package and its missing dependencies (e.g. notqmail)
pkg-get -di notqmail

# Install a single package without dependencies
pkg-get -i <package>
```

> **Note:** On a default Irradium installation, `contrib`, `irradium-contrib`, and `irradium-xfce` are disabled by default (`.inactive` in `/etc/ports/` and commented out in `/etc/prt-get.conf`). To install packages or dependencies from those collections, remove the `.inactive` suffix in `/etc/ports/`, uncomment their `prtdir` lines in `/etc/prt-get.conf`, and run `ports -u`.

---

## Available Packages

Packages available on this mirror are tracked in two lists:

* [`packages/build.txt`](packages/build.txt): Packages compiled from source by this repository (including custom ports and CVE-patched overrides under [`ports/custom/`](ports/custom)).
* [`packages/upstream.txt`](packages/upstream.txt): Pre-built upstream Irradium packages verified and mirrored here so devices only need a single mirror and signing key.

Need another package from the Irradium or CRUX port trees? Open a pull request adding it to either list, or open an issue.

---

## Building Packages Locally

You can build and test packages locally on Linux or macOS using Docker:

```bash
# Clone the repository with upstream port submodules
git clone --recurse-submodules https://github.com/brennoo/irradium-packages.git
cd irradium-packages

# Build a package (and any missing dependencies) for riscv64
./builder/build-pkg.sh <package>
```
