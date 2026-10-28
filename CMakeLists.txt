cmake_minimum_required(VERSION 3.10...3.31)

project(zroxy LANGUAGES C)
include(CTest)

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Build options shared by every target
# ---------------------------------------------------------------------------
add_library(zroxy_build_options INTERFACE)
target_compile_features(zroxy_build_options INTERFACE c_std_11)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(zroxy_build_options INTERFACE
        -Wall -Wextra -Wno-unused-parameter)
endif()

# config.h, version.h and args.h live in src/.
add_library(zroxy_config INTERFACE)
target_include_directories(zroxy_config INTERFACE ${PROJECT_SOURCE_DIR}/src)

# zroxy_add_module(<name> INCLUDE <dir> SOURCES <src>... [DEPS <target>...])
#
# One static library per module. INCLUDE is the module's public header
# directory; DEPS are the modules whose headers or symbols it uses.
function(zroxy_add_module name)
    cmake_parse_arguments(ARG "" "INCLUDE" "SOURCES;DEPS;DEFINES" ${ARGN})
    add_library(${name} STATIC ${ARG_SOURCES})
    target_include_directories(${name} PUBLIC ${PROJECT_SOURCE_DIR}/${ARG_INCLUDE})
    target_link_libraries(${name}
        PUBLIC zroxy_config ${ARG_DEPS}
        PRIVATE zroxy_build_options)
    if(ARG_DEFINES)
        target_compile_definitions(${name} PUBLIC ${ARG_DEFINES})
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Modules (dependency order)
# ---------------------------------------------------------------------------
zroxy_add_module(zroxy_log
    INCLUDE log
    SOURCES log/log.c log/loglock.c
    DEPS Threads::Threads)

zroxy_add_module(zroxy_fifo
    INCLUDE fifo
    SOURCES fifo/fifo.c
    DEPS Threads::Threads)

zroxy_add_module(zroxy_net
    INCLUDE network
    SOURCES network/net.c network/net_io.c network/socks/socks.c
    DEPS zroxy_log)
target_include_directories(zroxy_net PUBLIC ${PROJECT_SOURCE_DIR}/network/socks)

# Included as <filter/filter.h>, so the public directory is sniproxy/.
zroxy_add_module(zroxy_filter
    INCLUDE sniproxy
    SOURCES sniproxy/filter/filter.c
    DEPS zroxy_log Threads::Threads)

zroxy_add_module(zroxy_stats
    INCLUDE statistics
    SOURCES statistics/statistics.c
    DEPS zroxy_log Threads::Threads)

zroxy_add_module(zroxy_monitor
    INCLUDE statistics
    SOURCES statistics/monitor.c
    DEPS zroxy_stats zroxy_net)

zroxy_add_module(zroxy_dns
    INCLUDE dnsproxy
    SOURCES dnsproxy/dns.c dnsproxy/dnsproxy.c dnsproxy/dnsserver.c
    DEPS zroxy_net zroxy_filter zroxy_stats zroxy_monitor zroxy_fifo)

set(ZROXY_SNI_SOURCES
    sniproxy/sniproxy.c
    sniproxy/sniclient.c
    sniproxy/sni_event_loop.c
    sniproxy/sni_resolver.c
)
set(ZROXY_SNI_DEPS zroxy_net zroxy_filter zroxy_stats)

zroxy_add_module(zroxy_sni
    INCLUDE sniproxy
    SOURCES ${ZROXY_SNI_SOURCES}
    DEPS ${ZROXY_SNI_DEPS})

zroxy_add_module(zroxy_args
    INCLUDE src
    SOURCES src/args.c
    DEPS zroxy_log zroxy_sni zroxy_dns)

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------
add_executable(zroxy src/main.c)
target_link_libraries(zroxy PRIVATE
    zroxy_args zroxy_sni zroxy_dns zroxy_monitor zroxy_filter zroxy_log
    zroxy_build_options)

install(TARGETS zroxy RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(BUILD_TESTING)
    # SNI engine builds with test hooks, once per event backend.
    zroxy_add_module(zroxy_sni_hooks
        INCLUDE sniproxy
        SOURCES ${ZROXY_SNI_SOURCES}
        DEPS ${ZROXY_SNI_DEPS}
        DEFINES SNI_TEST_HOOKS)
    zroxy_add_module(zroxy_sni_hooks_poll
        INCLUDE sniproxy
        SOURCES ${ZROXY_SNI_SOURCES}
        DEPS ${ZROXY_SNI_DEPS}
        DEFINES SNI_TEST_HOOKS SNI_FORCE_POLL)

    # zroxy_add_unit_test(<name> <source> <libs>...)
    # Builds test_<name> and registers it as ctest <name>.
    function(zroxy_add_unit_test name source)
        add_executable(test_${name} ${source})
        target_link_libraries(test_${name} PRIVATE ${ARGN} zroxy_build_options)
        add_test(NAME ${name} COMMAND test_${name})
    endfunction()

    add_test(NAME help_output COMMAND ${CMAKE_COMMAND}
        -DZROXY_BIN=$<TARGET_FILE:zroxy>
        -P ${PROJECT_SOURCE_DIR}/tests/check_help.cmake)

    zroxy_add_unit_test(net_host_extract tests/test_net_host_extract.c zroxy_net)
    zroxy_add_unit_test(filter_whitelist tests/test_filter_whitelist.c zroxy_filter)
    zroxy_add_unit_test(dns_codec        tests/test_dns_codec.c        zroxy_dns)
    zroxy_add_unit_test(args_parse       tests/test_args_parse.c       zroxy_args)
    zroxy_add_unit_test(socks_handshake  tests/test_socks_handshake.c  zroxy_net)
    zroxy_add_unit_test(sni_forwarding   tests/test_sni_forwarding.c   zroxy_sni)
    zroxy_add_unit_test(dnsproxy_tcp_io  tests/test_dnsproxy_tcp_io.c  zroxy_dns)
    zroxy_add_unit_test(io_limits        tests/test_io_limits.c        zroxy_dns zroxy_sni)
    zroxy_add_unit_test(sni_engine       tests/test_sni_engine.c       zroxy_sni_hooks)
    zroxy_add_unit_test(sni_engine_poll  tests/test_sni_engine.c       zroxy_sni_hooks_poll)

    set_tests_properties(sni_engine sni_engine_poll PROPERTIES TIMEOUT 180)
    set_tests_properties(io_limits PROPERTIES TIMEOUT 20)

    # Spawns the real binary; links nothing from the tree.
    add_executable(test_process tests/test_process.c)
    target_link_libraries(test_process PRIVATE zroxy_build_options)
    target_compile_definitions(test_process PRIVATE
        "ZROXY_BIN=\"$<TARGET_FILE:zroxy>\"")
    add_dependencies(test_process zroxy)
    add_test(NAME process_limits COMMAND test_process)
    set_tests_properties(process_limits PROPERTIES TIMEOUT 45)

    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        set(ZROXY_TEST_ENV "ZROXY_BIN=$<TARGET_FILE:zroxy>")
        foreach(e2e sni dns monitor)
            add_test(NAME ${e2e}_e2e
                COMMAND ${Python3_EXECUTABLE}
                    ${PROJECT_SOURCE_DIR}/tests/integration/test_${e2e}_e2e.py)
            set_tests_properties(${e2e}_e2e PROPERTIES
                TIMEOUT 90
                LABELS "integration;e2e"
                ENVIRONMENT "${ZROXY_TEST_ENV}")
        endforeach()

        # Stress and benchmark runs are local, but they are slower than the
        # default suite. DISABLED keeps them out of a plain ctest invocation.
        # Run them with: ctest --test-dir build -L stress --include-disabled
        add_test(NAME zroxy_stress
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/stress/zroxy_stress.py
                --duration 3
                --connections 8
                --workers 2
                --payload-size 1024
                --output ${CMAKE_BINARY_DIR}/stress-result.json)
        add_test(NAME zroxy_benchmark
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/benchmark/zroxy_benchmark.py
                --connections 4
                --payload-size 1024
                --duration 2
                --output ${CMAKE_BINARY_DIR}/benchmark-result.json)
        set_tests_properties(zroxy_stress PROPERTIES
            TIMEOUT 180
            LABELS "stress"
            DISABLED TRUE
            ENVIRONMENT "${ZROXY_TEST_ENV}")
        set_tests_properties(zroxy_benchmark PROPERTIES
            TIMEOUT 180
            LABELS "benchmark"
            DISABLED TRUE
            ENVIRONMENT "${ZROXY_TEST_ENV}")
    else()
        message(STATUS "Python3 not found; integration tests will not be registered")
    endif()
endif()
