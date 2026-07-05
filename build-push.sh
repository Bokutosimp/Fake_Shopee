#!/bin/sh
# Build the ShopStack image for the ISAG platform and push it to Harbor.
# Usage: ./build-push.sh [TAG]   (TAG defaults to "latest")
#
# Registry/project come from the platform manual: registry.ce-isag.com / isag-sf11.
# Build is forced to linux/amd64 because the platform runs amd64 nodes.
# NOTE: no EXPOSE in the Dockerfile on purpose — GZ::CTF maps internal port 80.
set -eu

REGISTRY="registry.ce-isag.com"
PROJECT="isag-sf11"
NAME="shopstack"
TAG="${1:-latest}"

IMAGE="${REGISTRY}/${PROJECT}/${NAME}:${TAG}"

echo "[*] Building ${IMAGE} (linux/amd64)"
docker build . --platform linux/amd64 -t "${IMAGE}"

echo "[*] Logging in to ${REGISTRY} (use the account issued by the platform admin)"
docker login "${REGISTRY}"

echo "[*] Pushing ${IMAGE}"
# Registry sits behind Cloudflare rate limits; retry once on a push failure.
if ! docker push "${IMAGE}"; then
    echo "[!] Push failed — waiting 15s and retrying once (Cloudflare limit?)" >&2
    sleep 15
    docker push "${IMAGE}"
fi

echo "[+] Done. Set the GZ::CTF challenge Container Image to:"
echo "    ${IMAGE}"
