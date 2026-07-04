find_package(unofficial-argon2 CONFIG REQUIRED)

add_library(PgoEngine STATIC Source/PgoEngine.cpp)

target_include_directories(PgoEngine PUBLIC Include)
target_link_libraries(PgoEngine PRIVATE unofficial::argon2::libargon2)

if(WIN32)
    target_link_libraries(PgoEngine PRIVATE bcrypt)
endif()
