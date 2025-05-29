/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#include "wkv.h"
#include <unity.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>

void setUp() {}

void tearDown() {}

namespace {

class Memory final
{
public:
    explicit Memory(const std::size_t fragments_cap) : fragments_cap_(fragments_cap) {}
    Memory(const Memory&)            = delete;
    Memory& operator=(const Memory&) = delete;
    Memory(Memory&&)                 = delete;
    Memory& operator=(Memory&&)      = delete;
    ~Memory() { TEST_ASSERT_EQUAL_size_t(0, fragments_); }

    [[nodiscard]] std::size_t get_fragments() const { return fragments_; }

    [[nodiscard]] std::size_t get_oom_count() const { return oom_count_; }

    void set_fragments_cap(const std::size_t fragments_cap)
    {
        TEST_ASSERT(fragments_cap > 0);
        fragments_cap_ = fragments_cap;
    }

    [[nodiscard]] static void* trampoline_realloc(wkv_t* const self, void* const ptr, const std::size_t new_size)
    {
        return static_cast<Memory*>(self->context)->realloc(ptr, new_size);
    }
    static void trampoline_free(wkv_t* const self, void* const ptr) { static_cast<Memory*>(self->context)->free(ptr); }

private:
    [[nodiscard]] void* realloc(void* const ptr, const std::size_t new_size)
    {
        TEST_ASSERT(new_size > 0);
        if (ptr == nullptr) {
            if (fragments_ < fragments_cap_) {
                ++fragments_;
                return std::malloc(new_size);
            }
        } else {
            if (fragments_ <= fragments_cap_) {
                return std::realloc(ptr, new_size);
            }
            --fragments_;
            std::free(ptr);
        }
        ++oom_count_;
        return nullptr;
    }

    void free(void* const ptr)
    {
        TEST_ASSERT(ptr != nullptr);
        TEST_ASSERT(fragments_ > 0);
        std::free(ptr);
        --fragments_;
    }

    std::size_t fragments_     = 0;
    std::size_t fragments_cap_ = 0;
    std::size_t oom_count_     = 0;
};

void test_basic()
{
    Memory mem(20);
    wkv_t  wkv   = wkv_init(Memory::trampoline_realloc, Memory::trampoline_free, &mem);
    char   foo[] = "foo";
    TEST_ASSERT_EQUAL_PTR(foo, wkv_add(&wkv, foo, '/', foo));
    char foo1[] = "/foo/";
    TEST_ASSERT_EQUAL_PTR(foo1, wkv_add(&wkv, foo1, '/', foo1));
    char foo2[] = "//foo//";
    TEST_ASSERT_EQUAL_PTR(foo2, wkv_add(&wkv, foo2, '/', foo2));
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
