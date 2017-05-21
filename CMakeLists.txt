cmake_minimum_required(VERSION 3.6)
project(pflogd)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_BUILD_TYPE Release)

add_executable(pflogd pflogd.c)
