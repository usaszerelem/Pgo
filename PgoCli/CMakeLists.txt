add_library(PgoCliLib STATIC Source/CommandLine.cpp)
target_include_directories(PgoCliLib PUBLIC Include)

add_executable(PgoCli Source/main.cpp)

target_link_libraries(PgoCli PRIVATE PgoEngine PgoCliLib)
