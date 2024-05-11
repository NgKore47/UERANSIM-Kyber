cmake_minimum_required(VERSION 3.17)
project(ueransim)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

include_directories(src)


#################### SUB DIRECTORIES ####################

add_subdirectory(src/ext)
add_subdirectory(src/utils)
add_subdirectory(src/asn/asn1c)
add_subdirectory(src/asn/rrc)
add_subdirectory(src/asn/ngap)
add_subdirectory(src/lib)
add_subdirectory(src/gnb)
add_subdirectory(src/ue)


# Add lib & executable
add_library(kemlib STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/ext/compact25519/kem.c)

# add_executable(kem ${CMAKE_CURRENT_SOURCE_DIR}/src/ext/compact25519/kem.c)

# Find the OQS library
find_library(OQS_LIBRARY NAMES oqs PATHS "/usr/local/lib")
find_package(OpenSSL REQUIRED)

if(NOT OQS_LIBRARY)
    message(FATAL_ERROR "liboqs not found")
else()
    message(STATUS "Found liboqs: ${OQS_LIBRARY}")
endif()

# Include directories
target_include_directories(kemlib PUBLIC
    "/usr/local/include/oqs"
    "${CMAKE_SOURCE_DIR}/src/ext/compact25519/"
    "${CMAKE_SOURCE_DIR}/src/ext/compact25519/c25519"
)

# Link libraries
target_link_libraries(kemlib PUBLIC 
    ${OQS_LIBRARY} 
    ${OPENSSL_LIBRARIES}
)

# Compiler options
# target_compile_options(kem PRIVATE -Wall -O2)

# Set RPATH
# set_target_properties(kem PROPERTIES INSTALL_RPATH "/usr/local/lib")

# target_link_libraries(kem PRIVATE kemlib)


#################### GNB EXECUTABLE ####################

add_executable(nr-gnb src/gnb.cpp)

target_link_libraries(nr-gnb pthread)

target_compile_options(nr-gnb PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-gnb asn-rrc)
target_link_libraries(nr-gnb asn-ngap)
target_link_libraries(nr-gnb common-lib)
target_link_libraries(nr-gnb gnb)

#################### UE EXECUTABLE ####################

add_executable(nr-ue src/ue.cpp)
target_include_directories(nr-ue PRIVATE src/ext/compact25519/)
target_link_libraries(nr-ue pthread)
target_compile_options(nr-ue PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-ue common-lib)
target_link_libraries(nr-ue ue)
target_link_libraries(nr-ue kemlib)

###################### IF BINDER ######################
add_library(devbnd SHARED src/binder.cpp)
target_compile_options(devbnd PRIVATE -D_GNU_SOURCE -Wall -Wextra)
target_link_options(devbnd PRIVATE -nostartfiles)
target_link_libraries(devbnd dl)

#################### CLI EXECUTABLE ####################
add_executable(nr-cli src/cli.cpp)
target_link_libraries(nr-cli pthread)
target_compile_options(nr-cli PRIVATE -Wall -Wextra -pedantic)

target_link_libraries(nr-cli common-lib)

#### KEM ####


# add_library(oqs SHARED)
# target_sources(oqs PUBLIC /usr/local/lib/liboqs.so)
# set_target_properties(oqs PROPERTIES LINKER_LANGUAGE CXX)
# target_compile_options(oqs PUBLIC "-loqs")

# # target_include_directories(kem PUBLIC /usr/local/lib/liboqs/build/include/)
# # # target_link_directories(kem PRIVATE oqs)
# # target_link_libraries(kem PRIVATE oqs)

# add_dependencies(kem oqs)
# target_link_libraries(kem PRIVATE oqs)

# target_include_directories(kem PUBLIC ${CMAKE_SOURCE_DIR}/src/ext/compact25519/)
# target_include_directories(kem PUBLIC ${CMAKE_SOURCE_DIR}/src/ext/compact25519/c25519)

# set_target_properties(kem PROPERTIES INSTALL_RPATH "/usr/local/lib")

# add_executable(kem ${CMAKE_SOURCE_DIR}/src/ext/compact25519/kem.c)

# # Find the OQS library
# find_library(OQS_LIBRARY NAMES oqs PATHS "/usr/local/lib")
# find_package(OpenSSL REQUIRED)


# if(NOT OQS_LIBRARY)
#     message(FATAL_ERROR "liboqs not found")
# else()
#     message(STATUS "Found liboqs: ${OQS_LIBRARY}")
# endif()

# include_directories("/usr/local/include/oqs")
# link_directories("/usr/local/lib")

# target_include_directories(kem PUBLIC "/usr/local/include/oqs")

# target_link_libraries(kem PUBLIC ${OQS_LIBRARY} ${OPENSSL_LIBRARIES})

# target_include_directories(kem PUBLIC ${CMAKE_SOURCE_DIR}/src/ext/compact25519/)
# target_include_directories(kem PUBLIC ${CMAKE_SOURCE_DIR}/src/ext/compact25519/c25519)
# target_link_options(kem PUBLIC -L/usr/local/lib)
# target_compile_options(kem PRIVATE -Wall -O2)

# # Set RPATH
# set_target_properties(kem PROPERTIES INSTALL_RPATH "/usr/local/lib")


