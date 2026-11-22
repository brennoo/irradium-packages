#!/bin/sh
# Bootstrap script for the irradium-packages binary mirror and custom-* ports.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/brennoo/irradium-packages/3.8/setup.sh | sh

set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    exit 1
fi

BRANCH="${BRANCH:-3.8}"
RAW_BASE="https://raw.githubusercontent.com/brennoo/irradium-packages/${BRANCH}"
MIRROR_URL="https://pkg.irradium.com.br/irradium/packages/ARCH/${BRANCH}"
CUSTOM_COLLECTIONS="custom-core custom-opt custom-xorg custom-xfce custom-contrib"

CURRENT_VER="$(irradium 2>/dev/null | awk '{print $3}' || true)"
if [ -n "${CURRENT_VER}" ] && [ "${CURRENT_VER}" != "${BRANCH}" ]; then
    echo "WARN: System reports Irradium ${CURRENT_VER}, while this mirror targets ${BRANCH}." >&2
    echo "      pkg-get filters /etc/pkg-get/mirrors by 'irradium' version (${CURRENT_VER})." >&2
fi

echo "==> Installing signify public key to /etc/pkg-get/pkg-get.pub..."
mkdir -p /etc/pkg-get /etc/ports /usr/ports
curl -fsSL "${RAW_BASE}/keys/pkg-get.pub" -o /etc/pkg-get/pkg-get.pub
chmod 0644 /etc/pkg-get/pkg-get.pub

echo "==> Configuring binary package mirror in /etc/pkg-get/mirrors..."
if [ -f /etc/pkg-get/mirrors ]; then
    sed -i 's|^https://|# https://|' /etc/pkg-get/mirrors
    sed -i "\|^# *${MIRROR_URL}\$|d; \|^${MIRROR_URL}\$|d" /etc/pkg-get/mirrors
fi
printf '%s\n' "${MIRROR_URL}" >> /etc/pkg-get/mirrors

echo "==> Configuring custom-* port collections in /etc/ports/..."
ACTIVE_CUSTOM=""
for col in ${CUSTOM_COLLECTIONS}; do
    cp /etc/pkg-get/pkg-get.pub "/etc/ports/${col}.pub"
    chmod 0644 "/etc/ports/${col}.pub"
    mkdir -p "/usr/ports/${col}"

    if curl -fsSI "${RAW_BASE}/ports/custom/${col}/REPO" >/dev/null 2>&1; then
        rm -f "/etc/ports/${col}.httpup.inactive"
        cat > "/etc/ports/${col}.httpup" << EOF
ROOT_DIR=/usr/ports/${col}
URL=${RAW_BASE}/ports/custom/${col}/
EOF
        chmod 0644 "/etc/ports/${col}.httpup"
        ACTIVE_CUSTOM="${ACTIVE_CUSTOM} ${col}"
    else
        rm -f "/etc/ports/${col}.httpup"
        cat > "/etc/ports/${col}.httpup.inactive" << EOF
ROOT_DIR=/usr/ports/${col}
URL=${RAW_BASE}/ports/custom/${col}/
EOF
        chmod 0644 "/etc/ports/${col}.httpup.inactive"
    fi
done

echo "==> Registering custom-* port directories in /etc/prt-get.conf..."
if [ -f /etc/prt-get.conf ]; then
    for col in ${CUSTOM_COLLECTIONS}; do
        sed -i "\|^[#[:space:]]*prtdir[[:space:]]\+/usr/ports/${col}\$|d" /etc/prt-get.conf
    done
    sed -i '1i prtdir /usr/ports/custom-core\nprtdir /usr/ports/custom-opt\nprtdir /usr/ports/custom-xorg\nprtdir /usr/ports/custom-xfce\nprtdir /usr/ports/custom-contrib' /etc/prt-get.conf
else
    cat > /etc/prt-get.conf << 'EOF'
prtdir /usr/ports/custom-core
prtdir /usr/ports/custom-opt
prtdir /usr/ports/custom-xorg
prtdir /usr/ports/custom-xfce
prtdir /usr/ports/custom-contrib
prtdir /usr/ports/irradium-core
prtdir /usr/ports/irradium-opt
prtdir /usr/ports/irradium-xorg
prtdir /usr/ports/core
prtdir /usr/ports/opt
prtdir /usr/ports/xorg
logfile  /var/log/pkgbuild/%n.log
runscripts yes
EOF
fi

if [ -n "${ACTIVE_CUSTOM}" ]; then
    echo "==> Syncing active custom port collections:${ACTIVE_CUSTOM}..."
    # shellcheck disable=SC2086
    ports -u ${ACTIVE_CUSTOM}
fi

echo "==> Setup complete! You can now install packages with: pkg-get -di <package>"
