# Set the minimum version of CMake that can be used
# To find the cmake version run
# $ cmake --version
cmake_minimum_required(VERSION 3.5)

# set name of Project
set(EXECUTABLE_NAME zroxy)

# Set the project name
project (${EXECUTABLE_NAME} C)



# check for pthread library
find_package(Threads REQUIRED)

# Create a sources variable with a link to all cpp files to compile
set(SOURCES
    src/main.c
    src/args.c
    
    sniproxy/sniproxy.c
    sniproxy/sniclient.c
    sniproxy/log/loglock.c
    sniproxy/log/log.c
    network/net.c
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
        ${PROJECT_SOURCE_DIR}/sniproxy
        ${PROJECT_SOURCE_DIR}/dnsproxy
        ${PROJECT_SOURCE_DIR}/statistics
        ${PROJECT_SOURCE_DIR}/network
        ${PROJECT_SOURCE_DIR}/network/socks
        ${PROJECT_SOURCE_DIR}/fifo
)

TARGET_LINK_LIBRARIES(${EXECUTABLE_NAME}
        pthread
)

INSTALL(TARGETS ${EXECUTABLE_NAME} RUNTIME DESTINATION bin)