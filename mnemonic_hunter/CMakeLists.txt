####################################################################################################################################################################################
if(WIN32)
    set(ZMQ_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/external/libzmq-v142-x64-4_3_4/")
    set(ZMQ_LIBRARIES "${CMAKE_SOURCE_DIR}/external/libzmq-v142-x64-4_3_4/libzmq-v142-mt-4_3_4.lib")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ZMQ REQUIRED libzmq)
endif()

####################################################################################################################################################################################
set(SRC
    main.cpp
    hd_wallet.cpp
    hd_wallet.h

    zmq_client.cpp
    zmq_client.h
)
add_executable(cuda-mnemonic-hunter ${SRC})

target_link_libraries(cuda-mnemonic-hunter PRIVATE util)
target_link_libraries(cuda-mnemonic-hunter PRIVATE Boost::log Boost::log_setup Boost::iostreams)
target_link_libraries(cuda-mnemonic-hunter PRIVATE wallycore secp256k1)
target_link_libraries(cuda-mnemonic-hunter PRIVATE nvinfer)
target_link_libraries(cuda-mnemonic-hunter PRIVATE ${ZMQ_LIBRARIES})
target_compile_definitions(cuda-mnemonic-hunter PRIVATE ZMQ_STATIC)
target_include_directories(cuda-mnemonic-hunter PRIVATE ${ZMQ_INCLUDE_DIR})
####################################################################################################################################################################################
