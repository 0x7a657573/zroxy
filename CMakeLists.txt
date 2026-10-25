# Set the minimum version of CMake that can be used
# To find the cmake version run
# $ cmake --version
cmake_minimum_required(VERSION 3.5)

# set name of Project
set(EXECUTABLE_NAME zroxy)

# Set the project name
project (${EXECUTABLE_NAME} C)
include(CTest)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

# Platform-specific configurations
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "Configuring for Linux")
    add_definitions(-D__linux__)
elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    message(STATUS "Configuring for FreeBSD")
#    add_definitions(-D__FreeBSD__)
endif()

# check for pthread library
find_package(Threads REQUIRED)

# Create a sources variable with a link to all cpp files to compile
set(SOURCES
    src/main.c
    src/args.c
    
    sniproxy/sniproxy.c
    sniproxy/sniclient.c
    log/loglock.c
    log/log.c
    network/net.c
    network/net_io.c
    network/socks/socks.c
    sniproxy/filter/filter.c
    statistics/monitor.c
    statistics/statistics.c
    dnsproxy/dnsserver.c
    dnsproxy/dnsproxy.c
    dnsproxy/dns.c
    fifo/fifo.c
)

# Add an executable
add_executable(${EXECUTABLE_NAME} ${SOURCES})


# Set the directories that should be included in the build command for this target
# when running g++ these will be included as -I/directory/path/
target_include_directories(${EXECUTABLE_NAME}
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/log
        ${PROJECT_SOURCE_DIR}/sniproxy
        ${PROJECT_SOURCE_DIR}/dnsproxy
        ${PROJECT_SOURCE_DIR}/statistics
        ${PROJECT_SOURCE_DIR}/network
        ${PROJECT_SOURCE_DIR}/network/socks
        ${PROJECT_SOURCE_DIR}/fifo
)

TARGET_LINK_LIBRARIES(${EXECUTABLE_NAME}
        Threads::Threads
)

INSTALL(TARGETS ${EXECUTABLE_NAME} RUNTIME DESTINATION bin)

if(BUILD_TESTING)
    add_executable(test_net_host_extract
        tests/test_net_host_extract.c
        network/net.c
        network/net_io.c
        log/log.c
    )

    target_include_directories(test_net_host_extract
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/log
            ${PROJECT_SOURCE_DIR}/network
    )

    add_test(NAME net_host_extract COMMAND test_net_host_extract)

    add_executable(test_filter_whitelist
        tests/test_filter_whitelist.c
        sniproxy/filter/filter.c
        log/log.c
    )

    target_include_directories(test_filter_whitelist
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/log
            ${PROJECT_SOURCE_DIR}/sniproxy
    )

    target_link_libraries(test_filter_whitelist
        PRIVATE
            Threads::Threads
    )

    add_test(NAME filter_whitelist COMMAND test_filter_whitelist)

    add_executable(test_dns_codec
        tests/test_dns_codec.c
        dnsproxy/dns.c
        log/log.c
    )

    target_include_directories(test_dns_codec
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/log
            ${PROJECT_SOURCE_DIR}/dnsproxy
    )

    add_test(NAME dns_codec COMMAND test_dns_codec)

    add_executable(test_args_parse
        tests/test_args_parse.c
        src/args.c
        log/log.c
    )

    target_include_directories(test_args_parse
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/log
            ${PROJECT_SOURCE_DIR}/sniproxy
            ${PROJECT_SOURCE_DIR}/dnsproxy
            ${PROJECT_SOURCE_DIR}/network/socks
            ${PROJECT_SOURCE_DIR}/statistics
    )

    add_test(NAME args_parse COMMAND test_args_parse)

    add_executable(test_socks_handshake
        tests/test_socks_handshake.c
        network/socks/socks.c
        network/net.c
        network/net_io.c
        log/log.c
    )

    target_include_directories(test_socks_handshake
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/log
            ${PROJECT_SOURCE_DIR}/network
            ${PROJECT_SOURCE_DIR}/network/socks
    )

    target_link_libraries(test_socks_handshake
        PRIVATE
            Threads::Threads
    )

    add_test(NAME socks_handshake COMMAND test_socks_handshake)

    add_executable(test_sni_forwarding
        tests/test_sni_forwarding.c
        sniproxy/sniclient.c
        sniproxy/filter/filter.c
        network/net.c
        network/net_io.c
        network/socks/socks.c
        log/log.c
        statistics/statistics.c
    )

    target_include_directories(test_sni_forwarding
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/log
            ${PROJECT_SOURCE_DIR}/sniproxy
            ${PROJECT_SOURCE_DIR}/network
            ${PROJECT_SOURCE_DIR}/network/socks
            ${PROJECT_SOURCE_DIR}/statistics
    )

    target_link_libraries(test_sni_forwarding
        PRIVATE
            Threads::Threads
    )

    add_test(NAME sni_forwarding COMMAND test_sni_forwarding)

    add_executable(test_dnsproxy_tcp_io
        tests/test_dnsproxy_tcp_io.c
        dnsproxy/dnsproxy.c
        dnsproxy/dns.c
        fifo/fifo.c
        network/net.c
        network/net_io.c
        network/socks/socks.c
        sniproxy/filter/filter.c
        statistics/statistics.c
        log/log.c
    )

    target_include_directories(test_dnsproxy_tcp_io
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/log
            ${PROJECT_SOURCE_DIR}/dnsproxy
            ${PROJECT_SOURCE_DIR}/fifo
            ${PROJECT_SOURCE_DIR}/network
            ${PROJECT_SOURCE_DIR}/network/socks
            ${PROJECT_SOURCE_DIR}/sniproxy
            ${PROJECT_SOURCE_DIR}/statistics
    )

    target_link_libraries(test_dnsproxy_tcp_io
        PRIVATE
            Threads::Threads
    )

    add_test(NAME dnsproxy_tcp_io COMMAND test_dnsproxy_tcp_io)

    add_executable(test_io_limits
        tests/test_io_limits.c
        network/net_io.c
        network/net.c
        network/socks/socks.c
        dnsproxy/dnsproxy.c
        dnsproxy/dns.c
        fifo/fifo.c
        sniproxy/sniclient.c
        sniproxy/filter/filter.c
        statistics/statistics.c
        log/log.c
    )

    target_include_directories(test_io_limits
        PRIVATE
            ${PROJECT_SOURCE_DIR}/src
            ${PROJECT_SOURCE_DIR}/log
            ${PROJECT_SOURCE_DIR}/dnsproxy
            ${PROJECT_SOURCE_DIR}/fifo
            ${PROJECT_SOURCE_DIR}/network
            ${PROJECT_SOURCE_DIR}/network/socks
            ${PROJECT_SOURCE_DIR}/sniproxy
            ${PROJECT_SOURCE_DIR}/statistics
    )

    target_link_libraries(test_io_limits
        PRIVATE
            Threads::Threads
    )

    add_test(NAME io_limits COMMAND test_io_limits)
    set_tests_properties(io_limits PROPERTIES TIMEOUT 20)

    add_executable(test_process
        tests/test_process.c
    )

    target_compile_definitions(test_process
        PRIVATE
            "ZROXY_BIN=\"${CMAKE_BINARY_DIR}/zroxy\""
    )

    add_dependencies(test_process zroxy)
    add_test(NAME process_limits COMMAND test_process)
    set_tests_properties(process_limits PROPERTIES TIMEOUT 45)

    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        set(ZROXY_TEST_ENV "ZROXY_BIN=${CMAKE_BINARY_DIR}/zroxy")
        add_test(NAME sni_e2e
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/integration/test_sni_e2e.py)
        add_test(NAME dns_e2e
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/integration/test_dns_e2e.py)
        add_test(NAME monitor_e2e
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/integration/test_monitor_e2e.py)
        set_tests_properties(sni_e2e dns_e2e monitor_e2e PROPERTIES
            TIMEOUT 90
            LABELS "integration;e2e"
            ENVIRONMENT "${ZROXY_TEST_ENV}"
            REQUIRED_FILES "${CMAKE_BINARY_DIR}/zroxy"
        )

        # Stress and benchmark runs are local, but they are slower than the
        # default suite. DISABLED keeps them out of a plain ctest invocation.
        # Run them with: ctest --test-dir build -L stress --include-disabled
        add_test(NAME zroxy_stress
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/stress/zroxy_stress.py
                --duration 3
                --connections 8
                --workers 2
                --payload-size 1024
                --output ${CMAKE_BINARY_DIR}/stress-result.json)
        add_test(NAME zroxy_benchmark
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/benchmark/zroxy_benchmark.py
                --connections 4
                --payload-size 1024
                --duration 2
                --output ${CMAKE_BINARY_DIR}/benchmark-result.json)
        set_tests_properties(zroxy_stress PROPERTIES
            TIMEOUT 180
            LABELS "stress"
            DISABLED TRUE
            ENVIRONMENT "${ZROXY_TEST_ENV}"
            REQUIRED_FILES "${CMAKE_BINARY_DIR}/zroxy"
        )
        set_tests_properties(zroxy_benchmark PROPERTIES
            TIMEOUT 180
            LABELS "benchmark"
            DISABLED TRUE
            ENVIRONMENT "${ZROXY_TEST_ENV}"
            REQUIRED_FILES "${CMAKE_BINARY_DIR}/zroxy"
        )
    else()
        message(STATUS "Python3 not found; integration tests will not be registered")
    endif()
endif()
