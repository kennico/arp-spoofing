cmake_minimum_required(VERSION 3.10)
project(arp_sproofing)

set(CMAKE_CXX_STANDARD 11)

add_executable(spoof spoof.cpp)
add_executable(inject inject.cpp)
