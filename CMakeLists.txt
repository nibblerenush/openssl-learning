cmake_minimum_required(VERSION 3.0)
project(openssl-learning)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  message("OPENSSL_VERSION: " ${OPENSSL_VERSION})
  message("OPENSSL_LIBRARIES: " ${OPENSSL_LIBRARIES})
endif()

add_executable(${PROJECT_NAME}-ssl ssl-main.cpp)
target_link_libraries(${PROJECT_NAME}-ssl OpenSSL::Crypto OpenSSL::SSL)

add_executable(${PROJECT_NAME}-crypto crypto-main.cpp)
target_link_libraries(${PROJECT_NAME}-crypto OpenSSL::Crypto OpenSSL::SSL)
