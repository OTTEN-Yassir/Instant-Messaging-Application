cmake_minimum_required(VERSION 3.0.0)
project(MessagerieServer VERSION 0.1.0 LANGUAGES C CXX)

include(CTest)
enable_testing()

add_executable(MessagerieServer 
    base64.h database.h server.h message.h
    src/server.cpp src/database.cpp src/base64.cpp main.cpp
)

target_link_libraries(MessagerieServer
    PRIVATE
        sqlite3
        ssl
        crypto
)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
