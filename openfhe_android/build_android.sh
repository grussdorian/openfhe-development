#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

NDK=${NDK:-"path/to/android-ndk-r29"}
API=29
BUILD_TYPE=Release

build_one() {
    ABI=$1

    BUILD_DIR="${SCRIPT_DIR}/build-${ABI}"
    INSTALL_DIR="${SCRIPT_DIR}/install-${ABI}"

    rm -rf "${BUILD_DIR}" "${INSTALL_DIR}"

    cmake -S "${SRC_DIR}" -B "${BUILD_DIR}" \
        -DCMAKE_TOOLCHAIN_FILE=${NDK}/build/cmake/android.toolchain.cmake \
        -DANDROID_ABI=${ABI} \
        -DANDROID_PLATFORM=android-${API} \
        -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
        -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} \
        \
        -DBUILD_STATIC=ON \
        -DBUILD_SHARED=OFF \
        -DBUILD_UNITTESTS=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_BENCHMARKS=OFF \
        -DBUILD_EXTRAS=OFF \
        \
        -DWITH_OPENMP=OFF \
        -DWITH_NATIVEOPT=OFF \
        -DWITH_TCM=OFF \
        -DWITH_NTL=OFF \
        -DWITH_BE2=OFF \
        -DWITH_BE4=ON \
        -DMATHBACKEND=4 \
        -DNATIVE_SIZE=64 \
        \
        -DCMAKE_C_FLAGS_RELEASE="-O3" \
        -DCMAKE_CXX_FLAGS_RELEASE="-O3 -Wno-error -Wno-unused-variable"

    cmake --build "${BUILD_DIR}" \
        --target OPENFHEcore_static OPENFHEpke_static OPENFHEbinfhe_static openfhe_android \
        -j 8

    cmake --install "${BUILD_DIR}"
}

build_one arm64-v8a
build_one x86_64

echo "[OK] Android static libs built."