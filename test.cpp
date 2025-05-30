/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#include "wkv.h"
#include <unity.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <algorithm>
#include <string_view>
#include <string>
#include <vector>

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

    // ReSharper disable once CppParameterMayBeConstPtrOrRef
    [[nodiscard]] static void* trampoline(wkv_t* const self, void* const ptr, const std::size_t new_size)
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
        if (edge->node.value != nullptr) {
            (void)std::snprintf(payload, sizeof(payload), "%p", edge->node.value);
        } else {
            payload[0] = '\0';
        }
        std::printf("%*s#%zu '%s': %s\n", indent, "", i, edge->seg, payload);
        print(&edge->node, depth + 1);
    }
}

[[nodiscard]] std::size_t count(const ::wkv_node_t* const node)
{
    std::size_t c = (node->value != nullptr) ? 1 : 0;
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
    wkv_t  wkv = wkv_init(Memory::trampoline, &mem);

    // Insert some keys and check the count.
    TEST_ASSERT(wkv_is_empty(&wkv));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "foo", i2ptr(0xA)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_add(&wkv, "/foo/", i2ptr(0xB)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_add(&wkv, "//foo//", i2ptr(0xC)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_add(&wkv, "/foo/bar", i2ptr(0xD)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_add(&wkv, "/foo/bar/", i2ptr(0xE)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_add(&wkv, "/foo/bar/baz", i2ptr(0xF)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_add(&wkv, "", i2ptr(0x10)));
    TEST_ASSERT_EQUAL_size_t(7, count(&wkv));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_add(&wkv, "/foo/bar/", i2ptr(1))); // conflict, ignored
    TEST_ASSERT_EQUAL_size_t(7, count(&wkv));
    TEST_ASSERT_EQUAL_PTR(i2ptr(1), wkv_set(&wkv, "/foo/bar/", i2ptr(1))); // conflict, overwritten
    TEST_ASSERT_EQUAL_size_t(7, count(&wkv));
    TEST_ASSERT(!wkv_is_empty(&wkv));
    print(&wkv.root);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;

    // Get some keys.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_get(&wkv, "foo"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_get(&wkv, "/foo/"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_get(&wkv, "//foo//"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_get(&wkv, "/foo/bar"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_get(&wkv, "/foo/bar/"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_get(&wkv, "/foo/bar/baz"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_get(&wkv, ""));

    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get(&wkv, "nonexistent"));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get(&wkv, "foo/"));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get(&wkv, "/foo"));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get(&wkv, "//foo"));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get(&wkv, "/foo//"));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get(&wkv, "/nonexistent/"));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get(&wkv, "//nonexistent//"));

    // Delete some keys.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_del(&wkv, "foo"));
    TEST_ASSERT_EQUAL_size_t(6, count(&wkv));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_del(&wkv, "foo"));
    TEST_ASSERT_EQUAL_size_t(6, count(&wkv));

    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_del(&wkv, "/foo/"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_del(&wkv, "//foo//"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_del(&wkv, "/foo/bar"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_del(&wkv, "/foo/bar/"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_del(&wkv, "/foo/bar/baz"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_del(&wkv, ""));

    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT(wkv_is_empty(&wkv));
}

void test_long_keys()
{
    Memory mem(50);
    wkv_t  wkv = wkv_init(Memory::trampoline, &mem);

    char long_boy[WKV_KEY_MAX_LEN + 2];
    std::memset(long_boy, 'a', WKV_KEY_MAX_LEN);
    long_boy[WKV_KEY_MAX_LEN]     = 0;
    long_boy[WKV_KEY_MAX_LEN + 1] = 0;

    // Insert max length key successfully.
    TEST_ASSERT_EQUAL_size_t(WKV_KEY_MAX_LEN, std::strlen(long_boy));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_add(&wkv, long_boy, i2ptr(0x10)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_add(&wkv, long_boy, i2ptr(0x11))); // already exists
    TEST_ASSERT_EQUAL_size_t(1, count(&wkv));
    TEST_ASSERT(!wkv_is_empty(&wkv));

    // Insert longer key, which should fail.
    long_boy[WKV_KEY_MAX_LEN] = 'a';
    TEST_ASSERT_EQUAL_size_t(WKV_KEY_MAX_LEN + 1, std::strlen(long_boy));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, long_boy, i2ptr(0x12)));
    TEST_ASSERT_EQUAL_size_t(1, count(&wkv));
    TEST_ASSERT(!wkv_is_empty(&wkv));

    // Now, request a key that is too long.
    // If it were to be truncated, it would match the valid long key, which must not happen.
    long_boy[WKV_KEY_MAX_LEN] = 'a';
    TEST_ASSERT_EQUAL_size_t(WKV_KEY_MAX_LEN + 1, std::strlen(long_boy));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get(&wkv, long_boy));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_del(&wkv, long_boy));
    TEST_ASSERT_EQUAL_size_t(1, count(&wkv)); // still there!
    TEST_ASSERT(!wkv_is_empty(&wkv));

    // Cleanup.
    long_boy[WKV_KEY_MAX_LEN] = 0;
    TEST_ASSERT_EQUAL_size_t(WKV_KEY_MAX_LEN, std::strlen(long_boy));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_get(&wkv, long_boy));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_del(&wkv, long_boy));
    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT(wkv_is_empty(&wkv));
}

void test_backtrack()
{
    {
        Memory mem(0);
        wkv_t  wkv = wkv_init(Memory::trampoline, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a", i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(1);
        wkv_t  wkv = wkv_init(Memory::trampoline, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_set(&wkv, "a", i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(1, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(1);
        wkv_t  wkv = wkv_init(Memory::trampoline, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(1, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(2);
        wkv_t  wkv = wkv_init(Memory::trampoline, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_set(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(3);
        wkv_t  wkv = wkv_init(Memory::trampoline, &mem);
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(3, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(3); // top node A will be retained because it has a payload.
        wkv_t  wkv = wkv_init(Memory::trampoline, &mem);
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "a", i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments_peak());
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(3, mem.get_fragments_peak());
        TEST_ASSERT(!wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(1, count(&wkv));
        // cleanup
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_del(&wkv, "a"));
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(4); // top node A will be retained because it has a child.
        wkv_t  wkv = wkv_init(Memory::trampoline, &mem);
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_add(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments_peak());
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/c", i2ptr(0xC)));
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments_peak());
        TEST_ASSERT(!wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(1, count(&wkv));
        // cleanup
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_del(&wkv, "a/b"));
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
}

void test_reconstruct_key()
{
    Memory mem(50);
    wkv_t  wkv = wkv_init(Memory::trampoline, &mem);
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "xx/a", i2ptr(0xA)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_add(&wkv, "xx//b", i2ptr(0xB)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_add(&wkv, "", i2ptr(0xC)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_add(&wkv, "/", i2ptr(0xD)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_add(&wkv, "e", i2ptr(0xE)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_add(&wkv, "/xx//f/", i2ptr(0xF)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_add(&wkv, "//", i2ptr(0x1)));

    char buf[WKV_KEY_MAX_LEN + 1];

    const ::wkv_node_t* n = _wkv_get(&wkv, &wkv.root, { 4, "xx/a" });
    TEST_ASSERT(n->value == i2ptr(0xA));
    _wkv_reconstruct_key(n, 4, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("xx/a", buf);

    n = _wkv_get(&wkv, &wkv.root, { 5, "xx//b" });
    TEST_ASSERT(n->value == i2ptr(0xB));
    _wkv_reconstruct_key(n, 5, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("xx//b", buf);

    n = _wkv_get(&wkv, &wkv.root, { 0, "" });
    TEST_ASSERT(n->value == i2ptr(0xC));
    _wkv_reconstruct_key(n, 0, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("", buf);

    n = _wkv_get(&wkv, &wkv.root, { 1, "/" });
    TEST_ASSERT(n->value == i2ptr(0xD));
    _wkv_reconstruct_key(n, 1, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("/", buf);

    n = _wkv_get(&wkv, &wkv.root, { 1, "e" });
    TEST_ASSERT(n->value == i2ptr(0xE));
    _wkv_reconstruct_key(n, 1, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("e", buf);

    n = _wkv_get(&wkv, &wkv.root, { 7, "/xx//f/" });
    TEST_ASSERT(n->value == i2ptr(0xF));
    _wkv_reconstruct_key(n, 7, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("/xx//f/", buf);

    n = _wkv_get(&wkv, &wkv.root, { 2, "//" });
    TEST_ASSERT(n->value == i2ptr(0x1));
    _wkv_reconstruct_key(n, 2, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("//", buf);

    // cleanup
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_del(&wkv, "xx/a"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_del(&wkv, "xx//b"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_del(&wkv, ""));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_del(&wkv, "/"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_del(&wkv, "e"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_del(&wkv, "/xx//f/"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_del(&wkv, "//"));
    TEST_ASSERT(wkv_is_empty(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

[[nodiscard]] std::string_view view(const ::wkv_str_t& str)
{
    return std::string_view(str.str, str.len);
}

class MatchCollector final
{
public:
    struct Match
    {
        std::string              key;
        std::vector<std::string> substitutions;
        void*                    value = nullptr;

        explicit Match(const ::wkv_match_t& match) : key(view(match.key)), value(match.value)
        {
            const ::wkv_substitution_t* s = match.substitutions;
            while (s != nullptr) {
                substitutions.emplace_back(view(s->str));
                s = s->next;
            }
        }
    };

    [[nodiscard]] const std::vector<Match>& get_matches() const { return matches_; }

    [[nodiscard]] static void* trampoline(::wkv_t* const self, void* const context, const ::wkv_match_t match)
    {
        return static_cast<MatchCollector*>(context)->on_match(self, match);
    }

private:
    [[nodiscard]] void* on_match(::wkv_t*, const ::wkv_match_t match)
    {
        std::cout << "on_match: key='" << view(match.key) << "', value=" << match.value << std::endl;
        matches_.emplace_back(match);
        return nullptr;
    }

    std::vector<Match> matches_;
};

void test_get_all()
{
    Memory mem(50);
    wkv_t  wkv = wkv_init(Memory::trampoline, &mem);

    // Insert some keys.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "a", i2ptr(0xA)));

    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_add(&wkv, "a/b", i2ptr(0xB)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_add(&wkv, "a/b/1", i2ptr(0x1)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x2), wkv_add(&wkv, "a/b/2", i2ptr(0x2)));

    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_add(&wkv, "a/c", i2ptr(0xC)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x3), wkv_add(&wkv, "a/c/3", i2ptr(0x3)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x4), wkv_add(&wkv, "a/c/4", i2ptr(0x4)));

    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_add(&wkv, "a/d", i2ptr(0xD)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x5), wkv_add(&wkv, "a/d/5", i2ptr(0x5)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x6), wkv_add(&wkv, "a/d/6", i2ptr(0x6)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_add(&wkv, "a/d/6/e", i2ptr(0xE)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_add(&wkv, "a/d/6/f", i2ptr(0xF)));

    // Query literal match.
    {
        MatchCollector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_get_all(&wkv, "a", '*', &collector, MatchCollector::trampoline));
    }

    // Cleanup.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_del(&wkv, "a"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_del(&wkv, "a/b"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_del(&wkv, "a/b/1"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x2), wkv_del(&wkv, "a/b/2"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_del(&wkv, "a/c"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x3), wkv_del(&wkv, "a/c/3"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x4), wkv_del(&wkv, "a/c/4"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_del(&wkv, "a/d"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x5), wkv_del(&wkv, "a/d/5"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x6), wkv_del(&wkv, "a/d/6"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_del(&wkv, "a/d/6/e"));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_del(&wkv, "a/d/6/f"));
    TEST_ASSERT(wkv_is_empty(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
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
    RUN_TEST(test_long_keys);
    RUN_TEST(test_backtrack);
    RUN_TEST(test_reconstruct_key);
    RUN_TEST(test_get_all);
    return UNITY_END();
    // NOLINTEND(misc-include-cleaner)
}
