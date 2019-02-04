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

set(PKTHDRS
        include/fields.h
        include/netinfo.h
        include/pkt.h
        include/utils.h
        src/gateway.cpp src/hdrs.h src/misc.cpp src/netinfo.cpp)

add_executable(arpspf
        include/arpspf.h
        src/pthargs.h
        src/main.cpp
        ${PKTHDRS} src/pth-spoof.cpp src/pth-hjiack-http.cpp include/refactored-fields.h)
target_link_libraries(arpspf ${PCAP_LIBRARY} Threads::Threads)

add_executable(arpspf-test
        test/usage-unique_ptr.cpp test/header-test.cpp test/tmpl_traits-test.cpp
        ${PKTHDRS} test/usage-libpcap.cpp test/refactored_fields-test.cpp)
target_link_libraries(arpspf-test GTest::GTest GTest::Main ${PCAP_LIBRARY})

