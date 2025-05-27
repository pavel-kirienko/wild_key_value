/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#include "wildset.h"
#include <unity.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>

void setUp() {}

void tearDown() {}

namespace {

void test_basic()
{
    const wildset_t ws{};
    (void)ws;
}

} // namespace

int main(const int argc, const char* const argv[])
{
    const auto seed = static_cast<unsigned>((argc > 1) ? std::atoll(argv[1]) : std::time(nullptr)); // NOLINT
    std::printf("Randomness seed: %u\n", seed);
    std::srand(seed);
    // NOLINTBEGIN(misc-include-cleaner)
    UNITY_BEGIN();
    RUN_TEST(test_basic);
    return UNITY_END();
    // NOLINTEND(misc-include-cleaner)
}
