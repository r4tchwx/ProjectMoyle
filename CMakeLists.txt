cmake_minimum_required(VERSION 3.20)

project(ProjectMoyle
    VERSION 0.1.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Reviewed public core.
add_library(projectmoyle_core OBJECT
    src/launch_options.cpp
    src/resources.cpp
)

target_include_directories(projectmoyle_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Logging currently uses the Windows API.
if(WIN32)
    target_sources(projectmoyle_core PRIVATE src/log.cpp)
endif()

# ------------------------------------------------------------
# Tests that use synthetic/public-safe data only
# ------------------------------------------------------------

include(CTest)

if(BUILD_TESTING)

    add_executable(projectmoyle_cd_backing_test
        tests/cd_backing_test.cpp
    )
    target_include_directories(projectmoyle_cd_backing_test PRIVATE src)
    add_test(
        NAME cd_backing
        COMMAND projectmoyle_cd_backing_test
    )

    add_executable(projectmoyle_resources_test
        tests/resources_test.cpp
    )
    target_link_libraries(projectmoyle_resources_test PRIVATE projectmoyle_core)
    add_test(
        NAME resources
        COMMAND projectmoyle_resources_test
    )

    # Compiled as a regression/build check.
    # Execution requires the separately-reviewed GTE vector fixture,
    # which is intentionally not included in the initial public source set.
    add_executable(projectmoyle_gte_test
        tests/gte_test.cpp
    )
    target_include_directories(projectmoyle_gte_test PRIVATE src)

endif()

