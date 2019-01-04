cmake_minimum_required(VERSION 3.10)
project(arp_sproofing)

set(CMAKE_CXX_STANDARD 11)

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
        include/hdrs.h
        src/misc.cpp src/gateway.cpp)


add_executable(arpspf main.cpp ${COMMON_SOURCE})
target_link_libraries(arpspf ${PCAP_LIBRARY})

add_executable(fwd traffic_forwarding.cpp ${COMMON_SOURCE})
target_link_libraries(fwd ${PCAP_LIBRARY})



add_executable(get_packet demo_libpcap/get_packet.cpp ${COMMON_SOURCE})
target_link_libraries(get_packet ${PCAP_LIBRARY})

add_executable(fake_arp demo_libpcap/fake_arp.cpp ${COMMON_SOURCE})
target_link_libraries(fake_arp ${PCAP_LIBRARY})

add_executable(print_devices demo_libpcap/print_devices.cpp ${COMMON_SOURCE})
target_link_libraries(print_devices ${PCAP_LIBRARY})

add_executable(get_gateway demo_libpcap/get_gateway.cpp)
target_link_libraries(get_gateway Threads::Threads)

add_executable(arpspf-test test/modify_fields.cpp ${COMMON_SOURCE})
target_link_libraries(arpspf-test GTest::GTest GTest::Main)


