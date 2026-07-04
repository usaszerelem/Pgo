cmake_minimum_required(VERSION 3.16)
project(Pgo CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Standard hardening flags, applied to Release builds only (a Debug build has no
# reason to pay for stack protection / CFG / RELRO while stepping through a debugger).
if(MSVC)
    add_compile_options($<$<CONFIG:Release>:/sdl> $<$<CONFIG:Release>:/guard:cf>)
    add_link_options($<$<CONFIG:Release>:/DYNAMICBASE> $<$<CONFIG:Release>:/NXCOMPAT> $<$<CONFIG:Release>:/GUARD:CF>)
else()
    # Stack smashing protection and buffer overflow checks in libc calls (memcpy, sprintf, ...).
    # _FORTIFY_SOURCE requires optimization to be enabled, which Release builds already have.
    add_compile_options($<$<CONFIG:Release>:-fstack-protector-strong> $<$<CONFIG:Release>:-D_FORTIFY_SOURCE=2>)

    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        # PIE and RELRO/BIND_NOW are ELF/glibc-specific; macOS (Mach-O, PIE by default) and
        # Windows (handled by the MSVC branch above) don't use this linker syntax.
        add_compile_options($<$<CONFIG:Release>:-fPIE>)
        add_link_options($<$<CONFIG:Release>:-pie> $<$<CONFIG:Release>:-Wl,-z,relro,-z,now> $<$<CONFIG:Release>:-Wl,-z,noexecstack>)
    endif()
endif()

add_subdirectory(PgoEngine)
add_subdirectory(PgoCli)

option(PGO_BUILD_TESTS "Build GoogleTest-based automated tests" ON)
if(PGO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(Tests)
endif()
