cmake_minimum_required(VERSION 3.16)
project(Pgo CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(PgoEngine)
add_subdirectory(PgoCli)
