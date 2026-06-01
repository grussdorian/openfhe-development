cmake_minimum_required(VERSION 3.22.1)
project("openfhe_jni")

# Set the path to the prebuilt libraries install prefix
set(OPENFHE_INSTALL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../openfhe_android/install-${ANDROID_ABI}")

add_library(openfhe_jni SHARED
    jni_bridge.cpp
)

target_include_directories(openfhe_jni PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${OPENFHE_INSTALL_DIR}/include"
    "${OPENFHE_INSTALL_DIR}/include/openfhe"
)

# Link the static libraries in the correct order (pke -> binfhe -> core)
target_link_libraries(openfhe_jni PRIVATE
    "${OPENFHE_INSTALL_DIR}/lib/libopenfhe_android.a"
    "${OPENFHE_INSTALL_DIR}/lib/libOPENFHEpke_static.a"
    "${OPENFHE_INSTALL_DIR}/lib/libOPENFHEbinfhe_static.a"
    "${OPENFHE_INSTALL_DIR}/lib/libOPENFHEcore_static.a"
    log
)
