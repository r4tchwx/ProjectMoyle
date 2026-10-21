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


# Additional reviewed synthetic regression tests.
if(BUILD_TESTING)
    add_executable(projectmoyle_gte_mvmva_sqr_test tests/gte_mvmva_sqr_test.cpp)
    target_include_directories(projectmoyle_gte_mvmva_sqr_test PRIVATE src)
    add_test(NAME gte_mvmva_sqr COMMAND projectmoyle_gte_mvmva_sqr_test)

    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    foreach(proof_test IN ITEMS
        recomp_proof_test recomp_temporal_proof_test
        test_phase6d_addi_overflow test_phase6d_cop0_delay
        test_phase6d_r3000a_model test_phase6d_regimm_link
        test_phase6d_selfmod_fetch test_phase6d_syscall_summary)
        add_test(NAME ${proof_test}
            COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/${proof_test}.py)
        set_tests_properties(${proof_test} PROPERTIES
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    endforeach()
endif()
