#!/usr/bin/env bash
# ============================================================
# Build LightGBM 4.6.0 (Linux counterpart of build_lightgbm.bat)
# 1) Clones source + submodules if missing
# 2) Builds shared lib via CMake (no OpenMP dependency)
# Output: third_party/LightGBM/lib_lightgbm.so
# ============================================================
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/LightGBM"
REPO="https://github.com/microsoft/LightGBM.git"
TAG="v4.6.0"

if [ ! -d "$SRC_DIR/.git" ]; then
    echo "[1/3] Cloning LightGBM $TAG ..."
    git clone --depth 1 --branch "$TAG" "$REPO" "$SRC_DIR"
else
    echo "[1/3] LightGBM source already present, skipping clone"
fi

echo "[2/3] Updating submodules (fast_double_parser / fmt / compute) ..."
git -C "$SRC_DIR" submodule update --init --recursive --depth 1

echo "[3/3] Building ..."
cmake -S "$SRC_DIR" -B "$SRC_DIR/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DUSE_OPENMP=OFF \
    -DBUILD_CPP_TEST=OFF
cmake --build "$SRC_DIR/build" -j"$(nproc)"

echo "Done:"
ls -l "$SRC_DIR"/lib_lightgbm.* 2>/dev/null || \
    ls -l "$SRC_DIR"/build/lib_lightgbm.* 2>/dev/null || true
