cmake_minimum_required(VERSION 3.22.1)
project(registration)

set(CMAKE_CXX_STANDARD 20)
add_executable(registration main.cpp)

# Find the Crypto++ library
find_library(CRYPTOPP_LIB cryptopp)

# Link the Crypto++ library
target_link_libraries(registration PRIVATE ${CRYPTOPP_LIB})
