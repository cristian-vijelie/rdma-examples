cmake_minimum_required(VERSION 3.13)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

project(rdma_example C CXX)

find_package(PkgConfig REQUIRED)

link_libraries(ibverbs)

add_executable(rdma_receiver_busy_waiting_immediate rdma_receiver_busy_waiting_immediate.cpp)
add_executable(rdma_sender_busy_waiting_immediate rdma_sender_busy_waiting_immediate.cpp)
add_executable(rdma_receiver_event_send rdma_receiver_event_send.cpp)
add_executable(rdma_sender_event_send rdma_sender_event_send.cpp)
