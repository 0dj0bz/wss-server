cmake_minimum_required(VERSION 3.10)
project(WSS_Server)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-std=c++11 -O3")
set(SERVICE_COMPONENTS acm secretsmanager)

find_package(OpenSSL REQUIRED)
find_package(AWSSDK REQUIRED COMPONENTS ${SERVICE_COMPONENTS})

add_executable(wss_server main.cpp)

#target_include_directories(wss_server PRIVATE /path/to/websocketpp)
#target_include_directories(wss_server PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(wss_server PRIVATE ${AWSSDK_LINK_LIBRARIES} OpenSSL::SSL)