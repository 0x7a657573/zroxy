if(NOT DEFINED ZROXY_BIN)
    message(FATAL_ERROR "ZROXY_BIN is required")
endif()

foreach(HELP_ARG IN ITEMS "--help" "-h")
    execute_process(
        COMMAND "${ZROXY_BIN}" "${HELP_ARG}"
        RESULT_VARIABLE HELP_RESULT
        OUTPUT_VARIABLE HELP_OUTPUT
        ERROR_VARIABLE HELP_ERROR
    )

    if(NOT HELP_RESULT EQUAL 0)
        message(FATAL_ERROR "${HELP_ARG} returned ${HELP_RESULT}: ${HELP_ERROR}")
    endif()

    if(NOT HELP_ERROR STREQUAL "")
        message(FATAL_ERROR "${HELP_ARG} wrote to stderr: ${HELP_ERROR}")
    endif()

    foreach(REQUIRED_TEXT IN ITEMS
        "Usage: zroxy [OPTIONS]"
        "  -c, --config"
        "SNI proxy options:"
        "DNS proxy options:"
        "Monitor options:"
        "Examples:"
        "With no options, zroxy loads ./zroxy.conf."
    )
        string(FIND "${HELP_OUTPUT}" "${REQUIRED_TEXT}" TEXT_POSITION)
        if(TEXT_POSITION EQUAL -1)
            message(FATAL_ERROR "${HELP_ARG} is missing: ${REQUIRED_TEXT}")
        endif()
    endforeach()

    string(FIND "${HELP_OUTPUT}" "'config'" OLD_FORMAT_POSITION)
    if(NOT OLD_FORMAT_POSITION EQUAL -1)
        message(FATAL_ERROR "${HELP_ARG} still contains the old long-option format")
    endif()
endforeach()
