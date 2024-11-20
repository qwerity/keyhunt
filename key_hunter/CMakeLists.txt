####################################################################################################################################################################################
set(MAIN_SRC
    main.cpp
    key_hunter.cpp
    key_hunter.h
)
add_executable(cuda-keyhunt-pvk ${MAIN_SRC})
suppress_target_msvc_warnings(cuda-keyhunt-pvk)

target_link_libraries(cuda-keyhunt-pvk PRIVATE util)
target_link_libraries(cuda-keyhunt-pvk PRIVATE ecc_cuda)
target_link_libraries(cuda-keyhunt-pvk PRIVATE Boost::log Boost::log_setup Boost::iostreams)
####################################################################################################################################################################################
