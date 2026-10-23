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

# Second reviewed batch. All generated files stay in the local binary tree.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "Use a separate build directory (for example build/public).")
endif()
set(MOYLE_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${MOYLE_GENERATED}")

add_executable(DirectTitleGenerator tools/recomp/direct_title_main.cpp)
# Compile the harness even without proprietary inputs; linking/execution is opt-in.
add_library(projectmoyle_first_boot_harness OBJECT src/first_boot_main.cpp)
target_include_directories(projectmoyle_first_boot_harness PRIVATE src)
option(MOYLE_BUILD_FIRST_BOOT "Link the real first-boot harness using a local generated PAL unit" OFF)
set(MOYLE_FIRST_BOOT_UNIT "" CACHE FILEPATH "Locally generated PAL C++ unit inside this build directory")
if(MOYLE_BUILD_FIRST_BOOT)
    if(NOT EXISTS "${MOYLE_FIRST_BOOT_UNIT}")
        message(FATAL_ERROR "First boot requires a local generated PAL C++ unit from user-owned external input.")
    endif()
    file(REAL_PATH "${MOYLE_FIRST_BOOT_UNIT}" moyle_unit_real)
    file(REAL_PATH "${CMAKE_CURRENT_BINARY_DIR}" moyle_binary_real)
    file(RELATIVE_PATH moyle_unit_relative "${moyle_binary_real}" "${moyle_unit_real}")
    if(IS_ABSOLUTE "${moyle_unit_relative}" OR moyle_unit_relative MATCHES "^\\.\\.(/|$)")
        message(FATAL_ERROR "The generated PAL unit must remain inside the local build directory.")
    endif()
    add_executable(FirstBoot $<TARGET_OBJECTS:projectmoyle_first_boot_harness> "${moyle_unit_real}")
    target_include_directories(FirstBoot PRIVATE src)
    # No real-input execution is registered with CTest. EXE, map and disc are runtime arguments.
endif()

if(BUILD_TESTING)
    foreach(moyle_test IN ITEMS first_boot gpu_upload spu_dma)
        add_executable(projectmoyle_${moyle_test}_test tests/${moyle_test}_test.cpp)
        target_include_directories(projectmoyle_${moyle_test}_test PRIVATE src)
        add_test(NAME ${moyle_test} COMMAND projectmoyle_${moyle_test}_test)
    endforeach()
    add_executable(BootGeneratorTest tests/boot_generator_test.cpp)
    target_include_directories(BootGeneratorTest PRIVATE src)
    add_custom_command(OUTPUT "${MOYLE_GENERATED}/boot-synthetic.cpp" "${MOYLE_GENERATED}/boot-synthetic.map"
        COMMAND BootGeneratorTest "${MOYLE_GENERATED}/boot-synthetic.cpp" "${MOYLE_GENERATED}/boot-synthetic.map"
        DEPENDS BootGeneratorTest VERBATIM)
    add_executable(BootTest tests/boot_test.cpp "${MOYLE_GENERATED}/boot-synthetic.cpp")
    target_include_directories(BootTest PRIVATE src)
    add_test(NAME boot_generator COMMAND BootGeneratorTest "${MOYLE_GENERATED}/boot-ctest.cpp" "${MOYLE_GENERATED}/boot-ctest.map")
    add_test(NAME boot_runtime COMMAND BootTest "${MOYLE_GENERATED}/boot-synthetic.map")
endif()

# SHA-1 identity verification uses Windows CNG; do not replace it with a test shim.
if(WIN32)
    add_library(OverlayRecognition STATIC src/overlay_recognition.cpp)
    target_link_libraries(OverlayRecognition PRIVATE bcrypt)
    add_executable(OverlayUnitGenerator tools/recomp/overlay_main.cpp)
    target_link_libraries(OverlayUnitGenerator PRIVATE OverlayRecognition)
    if(BUILD_TESTING)
        add_executable(OverlayRecognitionTest tests/overlay_recognition_test.cpp)
        target_link_libraries(OverlayRecognitionTest PRIVATE OverlayRecognition)
        add_test(NAME overlay_recognition COMMAND OverlayRecognitionTest)
        add_executable(OverlayUnitGeneratorTest tests/overlay_unit_generator_test.cpp)
        target_link_libraries(OverlayUnitGeneratorTest PRIVATE OverlayRecognition)
        add_custom_command(OUTPUT "${MOYLE_GENERATED}/overlay-synthetic.cpp"
            COMMAND OverlayUnitGeneratorTest "${MOYLE_GENERATED}/overlay-synthetic.cpp"
            DEPENDS OverlayUnitGeneratorTest VERBATIM)
        add_executable(OverlayUnitTest tests/overlay_unit_test.cpp "${MOYLE_GENERATED}/overlay-synthetic.cpp")
        add_executable(OverlayDispatchTest tests/overlay_dispatch_test.cpp "${MOYLE_GENERATED}/overlay-synthetic.cpp")
        foreach(overlay_target IN ITEMS OverlayUnitTest OverlayDispatchTest)
            target_include_directories(${overlay_target} PRIVATE src)
            target_link_libraries(${overlay_target} PRIVATE OverlayRecognition)
        endforeach()
        add_test(NAME overlay_unit_generator COMMAND OverlayUnitGeneratorTest "${MOYLE_GENERATED}/overlay-ctest.cpp")
        add_test(NAME overlay_unit_runtime COMMAND OverlayUnitTest)
        add_test(NAME overlay_dispatch COMMAND OverlayDispatchTest)
    endif()
endif()
