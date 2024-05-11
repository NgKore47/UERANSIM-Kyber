file(GLOB_RECURSE H_FILES *.h)
file(GLOB_RECURSE C_FILES *.c)
file(GLOB_RECURSE HDR_FILES *.hpp)
file(GLOB_RECURSE SRC_FILES *.cpp)

add_library(ext ${H_FILES} ${C_FILES} ${HDR_FILES} ${SRC_FILES})

target_compile_options(ext PRIVATE -Wall -Wextra -pedantic -Wno-unused-parameter)
target_include_directories(ext PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})


# KEM #

# add_executable(kem ${CMAKE_CURRENT_SOURCE_DIR}/compact25519/kem.c)

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

# # target_link_directories(kem PUBLIC "/usr/local/include/oqs" )

# target_link_libraries(kem PUBLIC ${OQS_LIBRARY} PUBLIC ${OPENSSL_LIBRARIES})

# target_include_directories(kem PUBLIC ${CMAKE_SOURCE_DIR}/src/ext/compact25519/)
# target_include_directories(kem PUBLIC ${CMAKE_SOURCE_DIR}/src/ext/compact25519/c25519)


# target_compile_options(kem PRIVATE -Wall -O2)

# # Set RPATH
# set_target_properties(kem PROPERTIES INSTALL_RPATH "/usr/local/lib")

# set(INCLUDE_DIRS
#     "/usr/local/include/oqs"
#     "${CMAKE_SOURCE_DIR}/src/ext/compact25519/"
#     "${CMAKE_SOURCE_DIR}/src/ext/compact25519/c25519"
# )

# foreach(DIR IN LISTS INCLUDE_DIRS)
#     if(EXISTS "${DIR}")
#         message(STATUS "Including directory: ${DIR}")
#         target_include_directories(kem PUBLIC ${DIR})
#     else()
#         message(FATAL_ERROR "Include directory does not exist: ${DIR}")
#     endif()
# endforeach()


