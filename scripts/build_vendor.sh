#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VENDOR="reai_toolkit/vendor"

if ! command -v uv >/dev/null 2>&1; then
    echo "uv is not on PATH; see https://docs.astral.sh/uv/getting-started/install/" >&2
    exit 1
fi

echo "==> Rebuilding vendor tree at $VENDOR"
rm -rf "$VENDOR"
mkdir -p "$VENDOR"
uv pip install . --target "$VENDOR" --no-cache-dir

echo "==> Dropping the self-install so the checkout is not shadowed"
rm -rf "$VENDOR/reai_toolkit" "$VENDOR"/reai_toolkit-*.dist-info

echo "==> Vendored (this is what the plugin and the tests import)"
for dist in "$VENDOR"/*.dist-info; do
    [ -d "$dist" ] || continue
    name="$(basename "$dist" .dist-info)"
    case "$name" in
        revengai-* | libbs-* | pydantic-* | loguru-* | requests-*)
            echo "    ${name%-*} ${name##*-}"
            ;;
    esac
done

echo "==> $VENDOR is prepended to sys.path ahead of site-packages,"
echo "    so rerun this after any dependency change or the old tree wins."
