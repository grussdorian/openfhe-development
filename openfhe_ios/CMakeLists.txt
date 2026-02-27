add_library(openfhe_ios STATIC
    openfhe_ios.cpp
)

target_link_libraries(openfhe_ios
    PUBLIC
        OPENFHEcore_static
        OPENFHEpke_static
        OPENFHEbinfhe_static
)

# Explicitly add OpenFHE include directories
target_include_directories(openfhe_ios
    PUBLIC
        ${CMAKE_SOURCE_DIR}/src/core/include
        ${CMAKE_SOURCE_DIR}/src/pke/include
        ${CMAKE_SOURCE_DIR}/src/binfhe/include
        ${CMAKE_CURRENT_SOURCE_DIR}
)

install(TARGETS openfhe_ios
        ARCHIVE DESTINATION lib)

install(FILES openfhe_ios.h
        DESTINATION include)