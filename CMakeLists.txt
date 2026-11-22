cmake_minimum_required(VERSION 3.10...3.31)

project(zroxy LANGUAGES C)
include(CTest)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    string(REGEX MATCH "(^|[ \t])-O(0|1|2|3|s|z|fast|g)?([ \t]|$)" ZROXY_HAS_C_FLAGS_OPTIMIZATION
        "${CMAKE_C_FLAGS}")
    if(NOT ZROXY_HAS_C_FLAGS_OPTIMIZATION)
        set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
        set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
        message(STATUS "zroxy: no CMAKE_BUILD_TYPE given, using RelWithDebInfo")
    endif()
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Build options shared by every target
# ---------------------------------------------------------------------------
add_library(zroxy_build_options INTERFACE)
target_compile_features(zroxy_build_options INTERFACE c_std_11)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(zroxy_build_options INTERFACE
        -Wall -Wextra -Wno-unused-parameter -Wshadow -Wconversion)
endif()

option(ZROXY_HARDENING "Build with compiler and linker hardening flags" ON)
set(ZROXY_HARDENING_ENABLED)
if(ZROXY_HARDENING AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    include(CheckCCompilerFlag)

    set(ZROXY_C_FLAGS_FOR_CHECK "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}}")
    foreach(ZROXY_FLAG IN ITEMS -fstack-protector-strong -fstack-clash-protection -fcf-protection)
        string(REGEX REPLACE "[^A-Za-z0-9]" "_" ZROXY_FLAG_ID "${ZROXY_FLAG}")
        string(FIND "${ZROXY_C_FLAGS_FOR_CHECK}" "${ZROXY_FLAG}" ZROXY_FLAG_POS)
        set(ZROXY_NO_FLAG_POS -1)
        if(ZROXY_FLAG STREQUAL "-fstack-protector-strong")
            string(REGEX MATCH "-f(no-)?stack-protector" ZROXY_STACK_FLAG "${ZROXY_C_FLAGS_FOR_CHECK}")
            if(ZROXY_STACK_FLAG)
                set(ZROXY_NO_FLAG_POS 0)
            endif()
        elseif(ZROXY_FLAG STREQUAL "-fstack-clash-protection")
            string(FIND "${ZROXY_C_FLAGS_FOR_CHECK}" "-fno-stack-clash-protection" ZROXY_NO_FLAG_POS)
        elseif(ZROXY_FLAG STREQUAL "-fcf-protection")
            string(FIND "${ZROXY_C_FLAGS_FOR_CHECK}" "-fno-cf-protection" ZROXY_NO_FLAG_POS)
        endif()
        if(ZROXY_FLAG_POS EQUAL -1 AND ZROXY_NO_FLAG_POS EQUAL -1)
            check_c_compiler_flag("${ZROXY_FLAG}" ZROXY_ACCEPTS_${ZROXY_FLAG_ID})
            if(ZROXY_ACCEPTS_${ZROXY_FLAG_ID})
                target_compile_options(zroxy_build_options INTERFACE "${ZROXY_FLAG}")
                list(APPEND ZROXY_HARDENING_ENABLED "${ZROXY_FLAG}")
            endif()
        endif()
    endforeach()

    set(ZROXY_LINK_FLAGS_FOR_CHECK "${CMAKE_EXE_LINKER_FLAGS} ${CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE}}")
    if(NOT APPLE AND CMAKE_SYSTEM_NAME MATCHES "Linux|FreeBSD|OpenBSD|NetBSD|DragonFly")
        if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.18)
            include(CheckLinkerFlag)
        endif()
        foreach(ZROXY_FLAG IN ITEMS "-Wl,-z,relro" "-Wl,-z,now")
            string(REGEX REPLACE "[^A-Za-z0-9]" "_" ZROXY_FLAG_ID "${ZROXY_FLAG}")
            if(ZROXY_FLAG STREQUAL "-Wl,-z,relro")
                set(ZROXY_LINK_FEATURE relro)
            else()
                set(ZROXY_LINK_FEATURE now)
            endif()
            string(REGEX MATCH "(^|[ \t])(-Wl,)?-z((,|[ \t])norelro|norelro)([ \t]|$)" ZROXY_LINK_NORELRO
                "${ZROXY_LINK_FLAGS_FOR_CHECK}")
            string(REGEX MATCH "(^|[ \t])(-Wl,)?-z((,|[ \t])${ZROXY_LINK_FEATURE}|${ZROXY_LINK_FEATURE})([ \t]|$)" ZROXY_LINK_FLAG
                "${ZROXY_LINK_FLAGS_FOR_CHECK}")
            if(ZROXY_LINK_FLAG)
                set(ZROXY_LINK_FLAG_POS 0)
            else()
                set(ZROXY_LINK_FLAG_POS -1)
            endif()
            if(ZROXY_LINK_FEATURE STREQUAL "relro" AND ZROXY_LINK_NORELRO)
                set(ZROXY_LINK_FLAG_POS 0)
            endif()
            if(ZROXY_LINK_FLAG_POS EQUAL -1)
                if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.18)
                    check_linker_flag(C "${ZROXY_FLAG}" ZROXY_ACCEPTS_${ZROXY_FLAG_ID})
                else()
                    include(CheckCSourceCompiles)
                    set(CMAKE_REQUIRED_LINK_OPTIONS "${ZROXY_FLAG}")
                    set(CMAKE_REQUIRED_FLAGS "${CMAKE_C_FLAGS}")
                    check_c_source_compiles("int main(void) { return 0; }" ZROXY_ACCEPTS_${ZROXY_FLAG_ID})
                    unset(CMAKE_REQUIRED_LINK_OPTIONS)
                    unset(CMAKE_REQUIRED_FLAGS)
                endif()
                if(ZROXY_ACCEPTS_${ZROXY_FLAG_ID})
                    target_link_options(zroxy_build_options INTERFACE "${ZROXY_FLAG}")
                    list(APPEND ZROXY_HARDENING_ENABLED "${ZROXY_LINK_FEATURE}")
                endif()
            endif()
        endforeach()
    endif()

    string(REGEX MATCH "(^|[ \\t])[-/]D_FORTIFY_SOURCE([= ][0-9]+)?" ZROXY_HAS_FORTIFY "${ZROXY_C_FLAGS_FOR_CHECK}")
    string(REGEX MATCH "(^|[ \\t])-O(1|2|3|s|z|fast)([ \\t]|$)" ZROXY_HAS_OPTIMIZATION "${ZROXY_C_FLAGS_FOR_CHECK}")
    if(NOT ZROXY_HAS_FORTIFY AND NOT ZROXY_FUZZ AND
       (CMAKE_BUILD_TYPE MATCHES "^(Release|RelWithDebInfo|MinSizeRel)$" OR ZROXY_HAS_OPTIMIZATION OR CMAKE_CONFIGURATION_TYPES))
        if(CMAKE_CONFIGURATION_TYPES AND NOT ZROXY_HAS_OPTIMIZATION AND NOT CMAKE_BUILD_TYPE MATCHES "^(Release|RelWithDebInfo|MinSizeRel)$")
            target_compile_options(zroxy_build_options INTERFACE
                "$<$<NOT:$<CONFIG:Debug>>:-U_FORTIFY_SOURCE>"
                "$<$<NOT:$<CONFIG:Debug>>:-D_FORTIFY_SOURCE=3>")
        else()
            target_compile_options(zroxy_build_options INTERFACE -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3)
        endif()
        list(APPEND ZROXY_HARDENING_ENABLED "_FORTIFY_SOURCE=3")
    endif()
endif()
if(ZROXY_HARDENING_ENABLED)
    string(REPLACE ";" ", " ZROXY_HARDENING_STATUS "${ZROXY_HARDENING_ENABLED}")
else()
    set(ZROXY_HARDENING_STATUS "none")
endif()
set(ZROXY_HARDENING_HAS_RELRO FALSE)
set(ZROXY_HARDENING_HAS_NOW FALSE)
set(ZROXY_HARDENING_HAS_STACK FALSE)
set(ZROXY_HARDENING_HAS_FORTIFY FALSE)
if("relro" IN_LIST ZROXY_HARDENING_ENABLED)
    set(ZROXY_HARDENING_HAS_RELRO TRUE)
endif()
if("now" IN_LIST ZROXY_HARDENING_ENABLED)
    set(ZROXY_HARDENING_HAS_NOW TRUE)
endif()
if("-fstack-protector-strong" IN_LIST ZROXY_HARDENING_ENABLED)
    set(ZROXY_HARDENING_HAS_STACK TRUE)
endif()
if("_FORTIFY_SOURCE=3" IN_LIST ZROXY_HARDENING_ENABLED)
    set(ZROXY_HARDENING_HAS_FORTIFY TRUE)
endif()
message(STATUS "zroxy hardening: ${ZROXY_HARDENING_STATUS}")

# libFuzzer harnesses (tests/fuzz). Every module is built with coverage
# instrumentation and the sanitizers; the harnesses add the fuzzer runtime.
option(ZROXY_FUZZ "Build libFuzzer harnesses with ASan and UBSan (needs clang)" OFF)
if(ZROXY_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "ZROXY_FUZZ needs clang (CMAKE_C_COMPILER is ${CMAKE_C_COMPILER_ID})")
    endif()
    target_compile_options(zroxy_build_options INTERFACE
        -fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=undefined
        -fno-omit-frame-pointer -g)
    target_link_options(zroxy_build_options INTERFACE -fsanitize=address,undefined)
endif()

# Public headers: #include <zroxy/...>
add_library(zroxy_headers INTERFACE)
target_include_directories(zroxy_headers INTERFACE ${PROJECT_SOURCE_DIR}/include)

# zroxy_add_module(<name> SOURCES <src>... [DEPS <target>...] [DEFINES <def>...])
#
# One static library per module under src/<module>/. DEPS are the modules
# whose headers or symbols it uses.
function(zroxy_add_module name)
    cmake_parse_arguments(ARG "" "" "SOURCES;DEPS;DEFINES" ${ARGN})
    add_library(${name} STATIC ${ARG_SOURCES})
    target_link_libraries(${name}
        PUBLIC zroxy_headers ${ARG_DEPS}
        PRIVATE zroxy_build_options)
    if(ARG_DEFINES)
        target_compile_definitions(${name} PUBLIC ${ARG_DEFINES})
    endif()
endfunction()

# ---------------------------------------------------------------------------
# Modules (dependency order)
# ---------------------------------------------------------------------------
zroxy_add_module(zroxy_log
    SOURCES src/log/log.c
    DEPS Threads::Threads)

zroxy_add_module(zroxy_priv
    SOURCES src/priv/priv.c
    DEPS zroxy_log)

zroxy_add_module(zroxy_net
    SOURCES src/net/net.c src/net/net_io.c src/net/socks5_codec.c src/net/fdlimit.c src/net/acl.c
    DEPS zroxy_log)

# Readiness reactor (epoll or poll) shared by the SNI and DNS event loops.
zroxy_add_module(zroxy_core
    SOURCES src/core/reactor.c)
target_include_directories(zroxy_core PUBLIC ${PROJECT_SOURCE_DIR}/src/core)

# Hostname resolution is shared by the SNI and DNS data planes.  Keeping it
# outside either module prevents a second bounded resolver pool from being
# created when both services are enabled.
set(ZROXY_RESOLVER_SOURCES
    src/resolver/resolver.c
    src/resolver/resolver_policy.c
    src/resolver/resolver_infra.c
    src/resolver/resolver_sink.c
    src/resolver/resolver_test_hooks.c)

zroxy_add_module(zroxy_resolver
    SOURCES ${ZROXY_RESOLVER_SOURCES}
    DEPS zroxy_net zroxy_log Threads::Threads)
target_include_directories(zroxy_resolver PUBLIC ${PROJECT_SOURCE_DIR}/src/resolver)

# Resolver header for targets that compile resolver.c directly (test hooks).
add_library(zroxy_resolver_internal INTERFACE)
target_include_directories(zroxy_resolver_internal INTERFACE ${PROJECT_SOURCE_DIR}/src/resolver)

zroxy_add_module(zroxy_filter
    SOURCES src/filter/filter.c
    DEPS zroxy_log Threads::Threads)

zroxy_add_module(zroxy_stats
    SOURCES src/stats/statistics.c
    DEPS zroxy_log Threads::Threads)

zroxy_add_module(zroxy_monitor
    SOURCES src/stats/monitor.c
    DEPS zroxy_core zroxy_stats zroxy_net)

zroxy_add_module(zroxy_dns
    SOURCES src/dns/dns.c src/dns/dnscache.c src/dns/dnsrate.c src/dns/dnsproxy.c src/dns/dns_event_loop.c src/dns/dns_event_client.c src/dns/dns_event_upstream.c src/dns/dns_event_resolve.c src/dns/dnsserver.c
    DEPS zroxy_core zroxy_net zroxy_resolver zroxy_filter zroxy_stats)
target_include_directories(zroxy_dns PRIVATE ${PROJECT_SOURCE_DIR}/src/dns)

# DNS's own header stays private to src/dns/; tests that reach into it
# link zroxy_dns_internal.
add_library(zroxy_dns_internal INTERFACE)
target_include_directories(zroxy_dns_internal INTERFACE ${PROJECT_SOURCE_DIR}/src/dns)

# The SNI engine's own headers (event loop, client) stay private to
# src/sni/; tests that drive the engine directly link zroxy_sni_internal.
add_library(zroxy_sni_internal INTERFACE)
target_include_directories(zroxy_sni_internal INTERFACE ${PROJECT_SOURCE_DIR}/src/sni)

set(ZROXY_SNI_SOURCES
    src/sni/sniproxy.c
    src/sni/sni_conn_limit.c
    src/sni/sni_event_loop.c
    src/sni/sni_io.c
    src/sni/sni_relay.c
    src/sni/sni_test_hooks.c
    src/sni/sni_upstream.c
)
set(ZROXY_SNI_DEPS zroxy_core zroxy_net zroxy_resolver zroxy_filter zroxy_stats)

zroxy_add_module(zroxy_sni
    SOURCES ${ZROXY_SNI_SOURCES}
    DEPS ${ZROXY_SNI_DEPS})
target_include_directories(zroxy_sni PRIVATE ${PROJECT_SOURCE_DIR}/src/sni)

zroxy_add_module(zroxy_args
    SOURCES src/args/args.c src/args/args_options.c src/args/args_secret.c
    DEPS zroxy_log zroxy_net)
target_include_directories(zroxy_args PRIVATE ${PROJECT_SOURCE_DIR}/src/args)

# ---------------------------------------------------------------------------
# Executable
# ---------------------------------------------------------------------------
add_executable(zroxy src/main.c)
target_link_libraries(zroxy PRIVATE
    zroxy_args zroxy_priv zroxy_sni zroxy_dns zroxy_monitor zroxy_filter zroxy_log
    zroxy_build_options)

install(TARGETS zroxy RUNTIME DESTINATION bin)

# ---------------------------------------------------------------------------
# Fuzz harnesses
# ---------------------------------------------------------------------------
if(BUILD_TESTING OR ZROXY_FUZZ)
    add_subdirectory(tests/fuzz)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(BUILD_TESTING)
    # SNI engine builds with test hooks, once per event backend.
    zroxy_add_module(zroxy_sni_hooks
        SOURCES ${ZROXY_SNI_SOURCES} ${ZROXY_RESOLVER_SOURCES}
        DEPS zroxy_core zroxy_net zroxy_filter zroxy_stats zroxy_sni_internal zroxy_resolver_internal
        DEFINES SNI_TEST_HOOKS)
    zroxy_add_module(zroxy_sni_hooks_poll
        SOURCES ${ZROXY_SNI_SOURCES} ${ZROXY_RESOLVER_SOURCES}
        DEPS zroxy_core zroxy_net zroxy_filter zroxy_stats zroxy_sni_internal zroxy_resolver_internal
        DEFINES SNI_TEST_HOOKS SNI_FORCE_POLL)

    # Blocking helpers (dial, exact read, SOCKS5 client) only tests use.
    add_library(zroxy_test_support STATIC
        tests/support/net_blocking.c tests/support/socks_client.c)
    target_include_directories(zroxy_test_support PUBLIC tests/support)
    target_link_libraries(zroxy_test_support
        PUBLIC zroxy_net zroxy_log
        PRIVATE zroxy_build_options)

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

    find_program(ZROXY_READELF readelf)
    if(ZROXY_HARDENING AND ZROXY_READELF AND NOT APPLE AND
       CMAKE_SYSTEM_NAME MATCHES "Linux|FreeBSD|OpenBSD|NetBSD|DragonFly")
        add_test(NAME zroxy_hardening COMMAND ${CMAKE_COMMAND}
            -DREADELF=${ZROXY_READELF}
            -DZROXY_BIN=$<TARGET_FILE:zroxy>
            -DZROXY_HARDENING_RELRO=${ZROXY_HARDENING_HAS_RELRO}
            -DZROXY_HARDENING_NOW=${ZROXY_HARDENING_HAS_NOW}
            -DZROXY_HARDENING_STACK=${ZROXY_HARDENING_HAS_STACK}
            -DZROXY_HARDENING_FORTIFY=${ZROXY_HARDENING_HAS_FORTIFY}
            -P ${PROJECT_SOURCE_DIR}/tests/check_hardening.cmake)
    endif()

    find_program(ZROXY_SH sh)
    # OpenWrt's procd/UCI init test is not meaningful on an OpenBSD host.
    if(ZROXY_SH AND NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
        add_test(NAME openwrt_init_uci COMMAND ${ZROXY_SH}
            ${PROJECT_SOURCE_DIR}/tests/openwrt/test_init_uci.sh
            ${PROJECT_SOURCE_DIR}/openwrt/files/zroxy.init
            $<TARGET_FILE:zroxy>)
    endif()

    zroxy_add_unit_test(net_host_extract tests/test_net_host_extract.c zroxy_net zroxy_test_support)
    zroxy_add_unit_test(filter_whitelist tests/test_filter_whitelist.c zroxy_filter)
    zroxy_add_unit_test(dns_codec        tests/test_dns_codec.c        zroxy_dns)
    zroxy_add_unit_test(dns_cache        tests/test_dns_cache.c        zroxy_dns)
    zroxy_add_unit_test(acl               tests/test_acl.c              zroxy_net)
    zroxy_add_unit_test(fdlimit          tests/test_fdlimit.c          zroxy_net)
    zroxy_add_unit_test(dns_rate          tests/test_dns_rate.c         zroxy_dns)
    zroxy_add_unit_test(dns_throttle     tests/test_dns_throttle.c     zroxy_dns zroxy_dns_internal)
    zroxy_add_unit_test(args_parse       tests/test_args_parse.c       zroxy_args zroxy_dns zroxy_dns_internal)
    zroxy_add_unit_test(socks_handshake  tests/test_socks_handshake.c  zroxy_net zroxy_test_support)
    zroxy_add_unit_test(socks5_codec     tests/test_socks5_codec.c     zroxy_net)
    zroxy_add_unit_test(sni_forwarding   tests/test_sni_forwarding.c   zroxy_sni_hooks)
    zroxy_add_unit_test(sni_engine       tests/test_sni_engine.c       zroxy_sni_hooks)
    zroxy_add_unit_test(sni_engine_poll  tests/test_sni_engine.c       zroxy_sni_hooks_poll)

    set_tests_properties(sni_engine sni_engine_poll PROPERTIES TIMEOUT 180)

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
        foreach(e2e sni dns monitor lifecycle)
            add_test(NAME ${e2e}_e2e
                COMMAND ${Python3_EXECUTABLE}
                    ${PROJECT_SOURCE_DIR}/tests/integration/test_${e2e}_e2e.py)
            set_tests_properties(${e2e}_e2e PROPERTIES
                TIMEOUT 90
                LABELS "integration;e2e"
                ENVIRONMENT "${ZROXY_TEST_ENV}")
        endforeach()

        # Stress and benchmark runs are local, but they are slower than the
        # default suite. DISABLED keeps them out of a plain ctest invocation;
        # run their commands directly when collecting a local performance run.
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
        add_test(NAME zroxy_dns_benchmark
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/benchmark/dns_benchmark.py
                --workers 8
                --upstream-connections 8
                --duration 2
                --output ${CMAKE_BINARY_DIR}/dns-benchmark-result.json)
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
        set_tests_properties(zroxy_dns_benchmark PROPERTIES
            TIMEOUT 180
            LABELS "benchmark"
            DISABLED TRUE
            ENVIRONMENT "${ZROXY_TEST_ENV}")
    else()
        message(STATUS "Python3 not found; integration tests will not be registered")
    endif()
endif()
