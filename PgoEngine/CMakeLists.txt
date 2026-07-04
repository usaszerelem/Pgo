find_package(unofficial-sodium CONFIG REQUIRED)

add_library(PgoEngine STATIC Source/PgoEngine.cpp)

target_include_directories(PgoEngine PUBLIC Include)
target_link_libraries(PgoEngine PUBLIC unofficial-sodium::sodium)
