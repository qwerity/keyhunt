####################################################################################################################################################################################
set(SRC
    main.cpp
    hd_wallet.cpp
    hd_wallet.h
)
add_executable(cuda-mnemonic-hunter ${SRC})

target_link_libraries(cuda-mnemonic-hunter PRIVATE util)
target_link_libraries(cuda-mnemonic-hunter PRIVATE wallycore libsecp256k1)
target_link_libraries(cuda-mnemonic-hunter PRIVATE ecc_cuda)
####################################################################################################################################################################################
