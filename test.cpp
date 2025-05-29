/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#include "wkv.h"
#include <unity.h>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <algorithm>

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

    [[nodiscard]] std::size_t get_fragments_peak() const { return fragments_peak_; }

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

private:
    [[nodiscard]] void* realloc(void* const ptr, const std::size_t new_size)
    {
        if (new_size == 0) {
            TEST_ASSERT(ptr != nullptr);
            TEST_ASSERT(fragments_ > 0);
            std::free(ptr);
            --fragments_;
            return nullptr;
        }
        if (ptr == nullptr) {
            if (fragments_ < fragments_cap_) {
                ++fragments_;
                fragments_peak_ = std::max(fragments_peak_, fragments_);
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

    std::size_t fragments_      = 0;
    std::size_t fragments_peak_ = 0;
    std::size_t fragments_cap_  = 0;
    std::size_t oom_count_      = 0;
};

void print(const ::wkv_node_t* const node, const std::size_t depth = 0)
{
    const auto indent = static_cast<int>(depth * 2);
    for (std::size_t i = 0; i < node->n_edges; ++i) {
        const ::wkv_edge_t* const edge = node->edges[i];
        TEST_ASSERT(edge != nullptr);
        TEST_ASSERT_EQUAL_PTR(edge->node.parent, node);
        char payload[256];
        if (edge->node.payload != nullptr) {
            (void)std::snprintf(payload, sizeof(payload), "%p", edge->node.payload);
        } else {
            payload[0] = '\0';
        }
        std::printf("%*s#%zu '%s': %s\n", indent, "", i, edge->seg, payload);
        print(&edge->node, depth + 1);
    }
}

[[nodiscard]] std::size_t count(const ::wkv_node_t* const node)
{
    std::size_t c = (node->payload != nullptr) ? 1 : 0;
    for (std::size_t i = 0; i < node->n_edges; ++i) {
        const ::wkv_edge_t* const edge = node->edges[i];
        TEST_ASSERT(edge != nullptr);
        TEST_ASSERT_EQUAL_PTR(edge->node.parent, node);
        c += count(&edge->node);
    }
    return c;
}
[[nodiscard]] std::size_t count(const ::wkv_t* const node)
{
    return count(&node->root);
}

[[nodiscard]] void* i2ptr(const auto i)
{
    return reinterpret_cast<void*>(i);
}

void test_basic()
{
    Memory mem(50);
    wkv_t  wkv = wkv_init(Memory::trampoline_realloc, &mem);
    TEST_ASSERT(wkv_is_empty(&wkv));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "foo", '/', i2ptr(0xA)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_add(&wkv, "/foo/", '/', i2ptr(0xB)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_add(&wkv, "//foo//", '/', i2ptr(0xC)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_add(&wkv, "/foo/bar", '/', i2ptr(0xD)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_add(&wkv, "/foo/bar/", '/', i2ptr(0xE)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_add(&wkv, "/foo/bar/", '/', i2ptr(1))); // conflict, ignored
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_add(&wkv, "/foo/bar/baz", '/', i2ptr(0xF)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_add(&wkv, "", '/', i2ptr(0x10)));
    TEST_ASSERT_EQUAL_size_t(7, count(&wkv));
    TEST_ASSERT(!wkv_is_empty(&wkv));
    print(&wkv.root);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;
}

void test_backtrack()
{
    {
        Memory mem(0);
        wkv_t  wkv = wkv_init(Memory::trampoline_realloc, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a", '/', i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(1);
        wkv_t  wkv = wkv_init(Memory::trampoline_realloc, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a", '/', i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(1, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(1);
        wkv_t  wkv = wkv_init(Memory::trampoline_realloc, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", '/', i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(1, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(2);
        wkv_t  wkv = wkv_init(Memory::trampoline_realloc, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", '/', i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(3);
        wkv_t  wkv = wkv_init(Memory::trampoline_realloc, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", '/', i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(3, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(3);
        wkv_t  wkv = wkv_init(Memory::trampoline_realloc, &mem);
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "a", '/', i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments_peak());
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", '/', i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(3, mem.get_fragments_peak());
        TEST_ASSERT(!wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(1, count(&wkv));
    }
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
    RUN_TEST(test_backtrack);
    return UNITY_END();
    // NOLINTEND(misc-include-cleaner)
}
