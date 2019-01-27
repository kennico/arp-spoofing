cmake_minimum_required(VERSION 3.10)
project(arp_sproofing)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DKNI_DEBUG")

# https://stackoverflow.com/a/29871891/8706476
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# https://cmake.org/cmake/help/v3.9/module/FindGTest.html
enable_testing()
find_package(GTest REQUIRED)

# https://github.com/bro/cmake/blob/master/FindPCAP.cmake
include(find_libpcap.cmake)

include_directories(${CMAKE_SOURCE_DIR}/include)

set(COMMON_SOURCE
        include/arpspf.h
        include/netinfo.h
        include/pkt.h
        src/hdrs.h
        include/fields.h
        src/misc.cpp src/gateway.cpp src/netinfo.cpp include/utils.h)


add_executable(arpspf src/main.cpp ${COMMON_SOURCE})
target_link_libraries(arpspf ${PCAP_LIBRARY} Threads::Threads)

add_executable(arpspf-test test/fields-test.cpp ${COMMON_SOURCE} test/usage-unique_ptr.cpp test/packet-test.cpp)
target_link_libraries(arpspf-test GTest::GTest GTest::Main ${PCAP_LIBRARY})


