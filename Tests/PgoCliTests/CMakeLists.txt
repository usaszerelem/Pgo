add_executable(PgoCliTests Source/CommandLineTests.cpp)

target_link_libraries(PgoCliTests PRIVATE PgoCliLib GTest::gtest GTest::gtest_main)

gtest_discover_tests(PgoCliTests)
