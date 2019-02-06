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

set(NETHEADERS
        include/netinfo.h
        include/pkt.h
        include/nethdrs.h
        include/utils.h
        src/hdrs.h
        src/misc.cpp src/gateway.cpp src/netinfo.cpp)


#add_executable(arpspf src/main.cpp ${COMMON_SOURCE})
#target_link_libraries(arpspf ${PCAP_LIBRARY} Threads::Threads)

add_executable(arpspf-test
        ${NETHEADERS}
        src/hdrs.h
        test/usage_tmpl_traits.cpp test/nethdrs_fields.cpp test/nethdrs_headers.cpp test/nethdrs_packets.cpp)
target_link_libraries(arpspf-test GTest::GTest GTest::Main ${PCAP_LIBRARY})

