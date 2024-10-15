function(suppress_msvc_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /wd5045)  # Spectre mitigation warning
        target_compile_options(${target} PRIVATE /wd4514)  # Unreferenced inline function removed
        target_compile_options(${target} PRIVATE /wd4668)  # #if not defined preprocessor issue
        target_compile_options(${target} PRIVATE /wd4365)  # Signed/unsigned mismatch
        target_compile_options(${target} PRIVATE /wd4820)  # Padding added after data member
        target_compile_options(${target} PRIVATE /wd4868)  # C4868: compiler may not enforce left-to-right evaluation order in braced initializer list
        target_compile_options(${target} PRIVATE /wd4710)  # C4710: function not inlined
        target_compile_options(${target} PRIVATE /wd4711)  # C4711: selected for automatic inline expansion
    endif()
endfunction()