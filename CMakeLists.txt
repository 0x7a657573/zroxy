# Set the minimum version of CMake that can be used
# To find the cmake version run
# $ cmake --version
cmake_minimum_required(VERSION 3.5)

# Set the project name
project (zroxy C)

# check for pthread library
find_package(Threads REQUIRED)

# Create a sources variable with a link to all cpp files to compile
set(SOURCES
    src/zroxy.c
    src/args.c
    socks/socks.c
    sniproxy/sniproxy.c
    sniproxy/sniclient.c
    sniproxy/log/loglock.c
    sniproxy/log/log.c
    network/net.c
    sniproxy/filter/filter.c
    statistics/monitor.c
    statistics/statistics.c
    dnsproxy/dnsserver.c
    dnsproxy/dnsproxy.c
)

# Add an executable
add_executable(zroxy ${SOURCES})

# Set the directories that should be included in the build command for this target
# when running g++ these will be included as -I/directory/path/
target_include_directories(zroxy
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/socks
        ${PROJECT_SOURCE_DIR}/sniproxy
        ${PROJECT_SOURCE_DIR}/dnsproxy
        ${PROJECT_SOURCE_DIR}/statistics
        ${PROJECT_SOURCE_DIR}/network
)

TARGET_LINK_LIBRARIES(zroxy
        pthread
)