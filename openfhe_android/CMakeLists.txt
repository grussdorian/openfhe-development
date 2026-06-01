add_library(openfhe_android STATIC
    openfhe_android.cpp
    execinfo.cpp
)

target_link_libraries(openfhe_android
    PUBLIC
        OPENFHEcore_static
        OPENFHEpke_static
        OPENFHEbinfhe_static
)

# Explicitly add OpenFHE include directories
target_include_directories(openfhe_android
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src/core/include
        ${CMAKE_SOURCE_DIR}/src/pke/include
        ${CMAKE_SOURCE_DIR}/src/binfhe/include
        ${CMAKE_CURRENT_SOURCE_DIR}
)

install(TARGETS openfhe_android
        ARCHIVE DESTINATION lib)

install(FILES openfhe_android.h
        DESTINATION include)