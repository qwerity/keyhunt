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
endfunction()
