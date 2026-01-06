function(suppress_target_msvc_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /wd5045)  # Spectre mitigation warning
        target_compile_options(${target} PRIVATE /wd4514)  # Unreferenced inline function removed
        target_compile_options(${target} PRIVATE /wd4668)  # #if not defined preprocessor issue
        target_compile_options(${target} PRIVATE /wd4365)  # Signed/unsigned mismatch
        target_compile_options(${target} PRIVATE /wd4820)  # Padding added after data member
        target_compile_options(${target} PRIVATE /wd4868)  # C4868: compiler may not enforce left-to-right evaluation order in braced initializer list
        target_compile_options(${target} PRIVATE /wd4710)  # C4710: function not inlined
        target_compile_options(${target} PRIVATE /wd4711)  # C4711: selected for automatic inline expansion
        target_compile_options(${target} PRIVATE /wd4530)  # C4530: C++ exception handler used, but unwind semantics are not enabled. Specify /EHsc
    endif()
endfunction()

function(suppress_msvc_warnings)
    if(MSVC)
        add_compile_options(
            /wd5045  # Spectre mitigation warning
            /wd4514  # Unreferenced inline function removed
            /wd4668  # #if not defined preprocessor issue
            /wd4365  # Signed/unsigned mismatch
            /wd4820  # Padding added after data member
            /wd4868  # C4868: compiler may not enforce left-to-right evaluation order in braced initializer list
            /wd4710  # C4710: function not inlined
            /wd4711  # C4711: selected for automatic inline expansion
            /wd4530  # C4530: C++ exception handler used, but unwind semantics are not enabled. Specify /EHsc
        )
    endif()
endfunction()

function(print_compiler_flags module)
    #message("${module}: CMAKE_C_FLAGS: ${CMAKE_C_FLAGS}")
    message("--- ${module}: CMAKE_CXX_FLAGS: ${CMAKE_CXX_FLAGS}")
    message("--- ${module}: CMAKE_CUDA_FLAGS: ${CMAKE_CUDA_FLAGS}")
endfunction()

function(configure_global_compilation_flags)
    # Set compiler options
    # Set the C++ compiler flags for Debug and Release configurations
    set(CMAKE_CXX_FLAGS_DEBUG "-Wall")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-Wall")

    if(WIN32)
        # Set _WIN32_WINNT and BOOST_USE_WINAPI_VERSION to target Windows 8
        set(WINAPI_VERSION 0x0602)
        add_definitions(-D_WIN32_WINNT=${WINAPI_VERSION} -DBOOST_USE_WINAPI_VERSION=${WINAPI_VERSION})

        add_compile_options($<$<COMPILE_LANGUAGE:CXX>:/Zc:__cplusplus>)

        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /fsanitize=address")
        set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /fsanitize=address")
    else()
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
        set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} -g")
    endif()
    ####################################################################################################################################################################################
endfunction()

function(fetch_and_include_needed_libs)
    include(FetchContent)

    ################################################################################################################################################################################
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    )
    FetchContent_MakeAvailable(nlohmann_json)

    include_directories(SYSTEM ${nlohmann_json_SOURCE_DIR}/include)
    ################################################################################################################################################################################
endfunction()

function(include_needed_libs)
    ################################################################################################################################################################################
    if(WIN32)
        set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/external/openssl")
    endif()
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL 3 REQUIRED)
    include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
    #################################################################################################################################################################################
    find_package(CUDAToolkit 13 EXACT REQUIRED)
    include_directories(SYSTEM ${CUDAToolkit_INCLUDE_DIRS})
    ################################################################################################################################################################################
    if(WIN32)
        set(BOOST_ROOT "C:/boost/boost-1.86.0/")
        set(BOOST_LIBRARYDIR "${BOOST_ROOT}/stage/lib")

        set(Boost_USE_STATIC_LIBS ON)
        set(Boost_USE_STATIC_RUNTIME ON)
        set(Boost_USE_MULTITHREADED ON)
        set(Boost_NO_WARN_NEW_VERSIONS ON)
    endif()

    find_package(Boost 1.80 REQUIRED COMPONENTS system log_setup log iostreams regex)
    include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
    ################################################################################################################################################################################
    link_directories(${CMAKE_SOURCE_DIR}/external/wallycore/lib)
    include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/external/wallycore/include)
    ################################################################################################################################################################################
endfunction()
