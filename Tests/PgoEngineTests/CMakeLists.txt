add_executable(PgoEngineTests Source/PgoEngineTests.cpp)

target_link_libraries(PgoEngineTests PRIVATE PgoEngine GTest::gtest GTest::gtest_main)

gtest_discover_tests(PgoEngineTests)
