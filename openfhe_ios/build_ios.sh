#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

IOS_DEPLOYMENT_TARGET="15.0"
BUILD_TYPE="Release"

build_one() {
    PLATFORM=$1
    ARCH=$2
    LABEL=$3

    BUILD_DIR="${SCRIPT_DIR}/build-${LABEL}"
    INSTALL_DIR="${SCRIPT_DIR}/install-${LABEL}"

    rm -rf "${BUILD_DIR}" "${INSTALL_DIR}"

    SDK_PATH=$(xcrun --sdk ${PLATFORM} --show-sdk-path)

    echo "=============================="
    echo "Building ${LABEL}"
    echo "=============================="

    cmake -S "${SRC_DIR}" -B "${BUILD_DIR}" \
        -DCMAKE_SYSTEM_NAME=iOS \
        -DCMAKE_OSX_ARCHITECTURES=${ARCH} \
        -DCMAKE_OSX_DEPLOYMENT_TARGET=${IOS_DEPLOYMENT_TARGET} \
        -DCMAKE_OSX_SYSROOT=${SDK_PATH} \
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
        --target OPENFHEcore_static OPENFHEpke_static openfhe_ios \
        -j $(sysctl -n hw.ncpu)

    cmake --install "${BUILD_DIR}"
}

create_xcframework() {
    DEVICE_DIR="${SCRIPT_DIR}/install-ios-device/lib"
    SIM_DIR="${SCRIPT_DIR}/install-ios-simulator/lib"

    XCFW_DIR="${SCRIPT_DIR}/OpenFHE.xcframework"
    rm -rf "${XCFW_DIR}"

    libtool -static -o "${DEVICE_DIR}/libOpenFHE_all.a" \
    "${DEVICE_DIR}/libOPENFHEcore_static.a" \
    "${DEVICE_DIR}/libOPENFHEpke_static.a" \
    "${DEVICE_DIR}/libOPENFHEbinfhe_static.a" \
    "${DEVICE_DIR}/libopenfhe_ios.a"

    libtool -static -o "${SIM_DIR}/libOpenFHE_all.a" \
        "${SIM_DIR}/libOPENFHEcore_static.a" \
        "${SIM_DIR}/libOPENFHEpke_static.a" \
        "${SIM_DIR}/libOPENFHEbinfhe_static.a" \
        "${SIM_DIR}/libopenfhe_ios.a"

    xcodebuild -create-xcframework \
        -library "${DEVICE_DIR}/libOpenFHE_all.a" \
        -headers "${SCRIPT_DIR}/install-ios-device/include" \
        -library "${SIM_DIR}/libOpenFHE_all.a" \
        -headers "${SCRIPT_DIR}/install-ios-simulator/include" \
        -output "${XCFW_DIR}"

    echo "[OK] XCFramework created at:"
    echo "${XCFW_DIR}"
}

TARGET="${1:-xcframework}"

case "${TARGET}" in
    device)
        build_one iphoneos arm64 ios-device
        ;;
    simulator)
        if [[ "$(uname -m)" == "arm64" ]]; then
            SIM_ARCH="arm64"
        else
            SIM_ARCH="x86_64"
        fi
        build_one iphonesimulator ${SIM_ARCH} ios-simulator
        ;;
    xcframework)
        build_one iphoneos arm64 ios-device

        if [[ "$(uname -m)" == "arm64" ]]; then
            SIM_ARCH="arm64"
        else
            SIM_ARCH="x86_64"
        fi

        build_one iphonesimulator ${SIM_ARCH} ios-simulator
        create_xcframework
        ;;
    *)
        echo "Usage: $0 [device|simulator|xcframework]"
        exit 1
        ;;
esac