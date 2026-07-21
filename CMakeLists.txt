cmake_minimum_required(VERSION 3.10)
project(Loguard VERSION 2.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Main binary
add_executable(loguard
    src/main.cpp
    src/util.cpp
    src/config.cpp
    src/telegram.cpp
    src/queue.cpp
    src/pam.cpp
    src/integrity.cpp
)

target_include_directories(loguard PRIVATE src)

# PAM hook binary
add_executable(loguard-notify
    src/pam_hook.c
)

# Installation
install(TARGETS loguard loguard-notify
    RUNTIME DESTINATION /opt/loguard/bin
)

# Version file
configure_file(version.txt ${CMAKE_BINARY_DIR}/version.txt COPYONLY)