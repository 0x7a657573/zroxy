# Fuzz harnesses, one per parser of untrusted input.
#
#   fuzz_<name>_replay  always built with BUILD_TESTING; runs every file of
#                       corpus/<name>/ through the harness (ctest fuzz_corpus_<name>)
#   fuzz_<name>         libFuzzer binary, built with -DZROXY_FUZZ=ON and clang
#
# See "Fuzzing" in the README.

# Builds with the static helpers monitor.c and filter.c keep to themselves.
zroxy_add_module(zroxy_monitor_hooks
    SOURCES ${PROJECT_SOURCE_DIR}/src/stats/monitor.c
    DEPS zroxy_stats zroxy_net
    DEFINES MON_TEST_HOOKS)
zroxy_add_module(zroxy_filter_hooks
    SOURCES ${PROJECT_SOURCE_DIR}/src/filter/filter.c
    DEPS zroxy_log Threads::Threads
    DEFINES FILTER_TEST_HOOKS)

# zroxy_add_fuzzer(<name> <source> <libs>...)
function(zroxy_add_fuzzer name source)
    add_library(fuzz_${name}_obj OBJECT ${source})
    target_include_directories(fuzz_${name}_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(fuzz_${name}_obj PRIVATE ${ARGN} zroxy_build_options)

    if(BUILD_TESTING)
        add_executable(fuzz_${name}_replay standalone_main.c $<TARGET_OBJECTS:fuzz_${name}_obj>)
        target_link_libraries(fuzz_${name}_replay PRIVATE ${ARGN} zroxy_build_options)
        add_test(NAME fuzz_corpus_${name}
            COMMAND fuzz_${name}_replay ${CMAKE_CURRENT_SOURCE_DIR}/corpus/${name})
        set_tests_properties(fuzz_corpus_${name} PROPERTIES TIMEOUT 60 LABELS "fuzz")
    endif()

    if(ZROXY_FUZZ)
        add_executable(fuzz_${name} $<TARGET_OBJECTS:fuzz_${name}_obj>)
        target_link_libraries(fuzz_${name} PRIVATE ${ARGN} zroxy_build_options)
        target_link_options(fuzz_${name} PRIVATE -fsanitize=fuzzer)
    endif()
endfunction()

zroxy_add_fuzzer(sni_host fuzz_sni_host.c
    zroxy_net zroxy_resolver zroxy_filter zroxy_sni_internal)
zroxy_add_fuzzer(dns fuzz_dns.c zroxy_dns)
zroxy_add_fuzzer(socks fuzz_socks.c zroxy_net Threads::Threads)
zroxy_add_fuzzer(monitor_request fuzz_monitor_request.c zroxy_monitor_hooks)
zroxy_add_fuzzer(config fuzz_config.c zroxy_filter_hooks zroxy_args)
