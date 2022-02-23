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
    src/Zroxy.c
    src/args.c
    Socks/socks.c
    SniProxy/SniProxy.c
    SniProxy/SniClient.c
    SniProxy/log/loglock.c
    SniProxy/log/log.c
    Network/net.c
    SniProxy/filter/filter.c
    Statistics/monitor.c
    Statistics/statistics.c
    DnsProxy/DnsServer.c
    DnsProxy/dnsproxy.c
)

# Add an executable
add_executable(zroxy ${SOURCES})

# Set the directories that should be included in the build command for this target
# when running g++ these will be included as -I/directory/path/
target_include_directories(zroxy
    PRIVATE 
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_SOURCE_DIR}/Socks
        ${PROJECT_SOURCE_DIR}/SniProxy
        ${PROJECT_SOURCE_DIR}/DnsProxy
        ${PROJECT_SOURCE_DIR}/Statistics
        ${PROJECT_SOURCE_DIR}/Network
)

TARGET_LINK_LIBRARIES(zroxy
        pthread
)