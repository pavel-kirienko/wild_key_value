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
#include <unordered_set>

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

[[nodiscard]] std::string_view view(const ::wkv_str_t& str)
{
    return (str.len > 0) ? std::string_view(str.str, str.len) : std::string_view("");
}

class Collector final
{
public:
    struct Hit
    {
        std::string              key;
        std::vector<std::string> substitutions;
        void*                    value = nullptr;

        explicit Hit(const ::wkv_hit_t& hit) : key(view(hit.key)), value(hit.value)
        {
            const ::wkv_substitution_t* s = hit.substitutions;
            while (s != nullptr) {
                substitutions.emplace_back(view(s->str));
                s = s->next;
            }
        }

        [[nodiscard]] bool check(const std::string_view          key,
                                 const std::vector<std::string>& substitutions,
                                 const void* const               value) const
        {
            return (this->key == key) && (this->substitutions.size() == substitutions.size()) &&
                   std::equal(this->substitutions.begin(), this->substitutions.end(), substitutions.begin()) &&
                   (this->value == value);
        }

        [[nodiscard]] std::string join_substitutions(const std::string_view sep = "/") const
        {
            std::string result;
            for (const auto& s : substitutions) {
                if (!result.empty()) {
                    result += sep;
                }
                result += s;
            }
            return result;
        }
    };

    [[nodiscard]] const std::vector<Hit>& get_matches() const { return matches_; }

    [[nodiscard]] const Hit& get_only() const
    {
        TEST_ASSERT_EQUAL_size_t(1, matches_.size());
        return matches_.front();
    }

    [[nodiscard]] static void* trampoline(::wkv_t* const self, void* const context, const ::wkv_hit_t hit)
    {
        return static_cast<Collector*>(context)->on_hit(self, hit);
    }

private:
    [[nodiscard]] void* on_hit(::wkv_t*, const ::wkv_hit_t hit)
    {
        matches_.emplace_back(hit);
        return nullptr;
    }

    std::vector<Hit> matches_;
};

void print(const ::wkv_node_t* const node, const std::size_t depth = 0)
{
    const auto indent = static_cast<int>(depth * 2);
    for (std::size_t i = 0; i < node->n_edges; ++i) {
        const ::wkv_edge_t* const edge = node->edges[i];
        TEST_ASSERT(edge != nullptr);
        TEST_ASSERT_EQUAL_PTR(edge->node.parent, node);
        char value[256];
        if (edge->node.value != nullptr) {
            (void)std::snprintf(value, sizeof(value), "%p", edge->node.value);
        } else {
            value[0] = '\0';
        }
        std::printf("%*s#%zu '%s': %s\n", indent, "", i, edge->seg, value);
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
    Memory mem(18);
    wkv_t  wkv  = wkv_init(Memory::trampoline);
    wkv.context = &mem;

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

    // Check indexing. Simply iterate until we get all keys and ensure that each occurred exactly once.
    {
        const size_t                    expected_count = count(&wkv);
        std::unordered_set<std::string> keys{ "foo", "/foo/", "//foo//", "/foo/bar", "/foo/bar/", "/foo/bar/baz", "" };
        for (size_t i = 0; i < expected_count; ++i) {
            char        key[WKV_KEY_MAX_LEN + 2];
            size_t      key_len = WKV_KEY_MAX_LEN + 1;
            void* const value   = wkv_at(&wkv, i, key, &key_len);
            TEST_ASSERT(value != nullptr);
            TEST_ASSERT(key_len <= WKV_KEY_MAX_LEN);
            TEST_ASSERT_EQUAL_size_t(1, keys.erase(key));
            TEST_ASSERT_EQUAL_size_t(key_len, std::strlen(key));

            // compare against the reference
            TEST_ASSERT_EQUAL_PTR(value, wkv_get(&wkv, key));

            // edge cases
            TEST_ASSERT_EQUAL_PTR(value, wkv_at(&wkv, i, nullptr, nullptr));
            TEST_ASSERT_EQUAL_PTR(value, wkv_at(&wkv, i, key, nullptr));
            TEST_ASSERT_EQUAL_PTR(value, wkv_at(&wkv, i, nullptr, &key_len));
            key_len = 0;
            TEST_ASSERT_EQUAL_PTR(value, wkv_at(&wkv, i, nullptr, &key_len));
            TEST_ASSERT_EQUAL_size_t(0, key_len);
        }
        TEST_ASSERT_EQUAL_size_t(0, keys.size());
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_at(&wkv, expected_count, nullptr, nullptr));
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_at(&wkv, 100, nullptr, nullptr));
    }

    // Delete some keys.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_set(&wkv, "foo", nullptr));
    TEST_ASSERT_EQUAL_size_t(6, count(&wkv));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_set(&wkv, "foo", nullptr));
    TEST_ASSERT_EQUAL_size_t(6, count(&wkv));

    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_set(&wkv, "/foo/", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_add(&wkv, "//foo//", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_add(&wkv, "/foo/bar", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_add(&wkv, "/foo/bar/", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_add(&wkv, "/foo/bar/baz", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_add(&wkv, "", nullptr));

    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT(wkv_is_empty(&wkv));

    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_at(&wkv, 0, nullptr, nullptr));
}

void test_long_keys()
{
    Memory mem(50);
    wkv_t  wkv  = wkv_init(Memory::trampoline);
    wkv.context = &mem;

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
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_set(&wkv, long_boy, nullptr));
    TEST_ASSERT_EQUAL_size_t(1, count(&wkv)); // still there!
    TEST_ASSERT(!wkv_is_empty(&wkv));

    // Wildcard query with a long key.
    Collector collector;
    long_boy[WKV_KEY_MAX_LEN] = 'a';
    TEST_ASSERT_EQUAL_size_t(WKV_KEY_MAX_LEN + 1, std::strlen(long_boy));
    TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, long_boy, nullptr, &collector, Collector::trampoline));

    // Cleanup.
    long_boy[WKV_KEY_MAX_LEN] = 0;
    TEST_ASSERT_EQUAL_size_t(WKV_KEY_MAX_LEN, std::strlen(long_boy));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_get(&wkv, long_boy));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x10), wkv_set(&wkv, long_boy, nullptr));
    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT(wkv_is_empty(&wkv));
}

void test_backtrack()
{
    {
        Memory mem(0);
        wkv_t  wkv  = wkv_init(Memory::trampoline);
        wkv.context = &mem;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a", i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(1);
        wkv_t  wkv  = wkv_init(Memory::trampoline);
        wkv.context = &mem;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_set(&wkv, "a", i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(1, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(1);
        wkv_t  wkv  = wkv_init(Memory::trampoline);
        wkv.context = &mem;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(1, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    }
    {
        Memory mem(2);
        wkv_t  wkv  = wkv_init(Memory::trampoline);
        wkv.context = &mem;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_set(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(3);
        wkv_t  wkv  = wkv_init(Memory::trampoline);
        wkv.context = &mem;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(3, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(3); // top node A will be retained because it has a payload.
        wkv_t  wkv  = wkv_init(Memory::trampoline);
        wkv.context = &mem;
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "a", i2ptr(0xA)));
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments_peak());
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(3, mem.get_fragments_peak());
        TEST_ASSERT(!wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(1, count(&wkv));
        // cleanup
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "a", nullptr));
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(4); // top node A will be retained because it has a child.
        wkv_t  wkv  = wkv_init(Memory::trampoline);
        wkv.context = &mem;
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_add(&wkv, "a/b", i2ptr(0xB)));
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments_peak());
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_add(&wkv, "a/c", i2ptr(0xC)));
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments_peak());
        TEST_ASSERT(!wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(1, count(&wkv));
        // cleanup
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_set(&wkv, "a/b", nullptr));
        TEST_ASSERT(wkv_is_empty(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
}

void test_reconstruct()
{
    Memory mem(50);
    wkv_t  wkv  = wkv_init(Memory::trampoline);
    wkv.context = &mem;
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
    _wkv_reconstruct(n, 4, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("xx/a", buf);

    n = _wkv_get(&wkv, &wkv.root, { 5, "xx//b" });
    TEST_ASSERT(n->value == i2ptr(0xB));
    _wkv_reconstruct(n, 5, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("xx//b", buf);

    n = _wkv_get(&wkv, &wkv.root, { 0, "" });
    TEST_ASSERT(n->value == i2ptr(0xC));
    _wkv_reconstruct(n, 0, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("", buf);

    n = _wkv_get(&wkv, &wkv.root, { 1, "/" });
    TEST_ASSERT(n->value == i2ptr(0xD));
    _wkv_reconstruct(n, 1, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("/", buf);

    n = _wkv_get(&wkv, &wkv.root, { 1, "e" });
    TEST_ASSERT(n->value == i2ptr(0xE));
    _wkv_reconstruct(n, 1, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("e", buf);

    n = _wkv_get(&wkv, &wkv.root, { 7, "/xx//f/" });
    TEST_ASSERT(n->value == i2ptr(0xF));
    _wkv_reconstruct(n, 7, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("/xx//f/", buf);

    n = _wkv_get(&wkv, &wkv.root, { 2, "//" });
    TEST_ASSERT(n->value == i2ptr(0x1));
    _wkv_reconstruct(n, 2, wkv.sep, buf);
    TEST_ASSERT_EQUAL_STRING("//", buf);

    // cleanup
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_set(&wkv, "xx/a", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_set(&wkv, "xx//b", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_set(&wkv, "", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_set(&wkv, "/", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_set(&wkv, "e", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_set(&wkv, "/xx//f/", nullptr));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_set(&wkv, "//", nullptr));
    TEST_ASSERT(wkv_is_empty(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_match()
{
    Memory mem(25);
    wkv_t  wkv  = wkv_init(Memory::trampoline);
    wkv.context = &mem;

    // Insert some keys.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA1), wkv_add(&wkv, "a1", i2ptr(0xa1)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA2), wkv_add(&wkv, "a2", i2ptr(0xa2)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), wkv_add(&wkv, "a", i2ptr(0xA)));

    TEST_ASSERT_EQUAL_PTR(i2ptr(0xB), wkv_add(&wkv, "a/b", i2ptr(0xB)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x1), wkv_add(&wkv, "a/b/1", i2ptr(0x1)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x2), wkv_add(&wkv, "a/b/2", i2ptr(0x2)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x100), wkv_add(&wkv, "x/b", i2ptr(0x100)));

    TEST_ASSERT_EQUAL_PTR(i2ptr(0xC), wkv_add(&wkv, "a/c", i2ptr(0xC)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x3), wkv_add(&wkv, "a/c/1", i2ptr(0x3)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x4), wkv_add(&wkv, "a/c/2", i2ptr(0x4)));

    TEST_ASSERT_EQUAL_PTR(i2ptr(0xD), wkv_add(&wkv, "a/d", i2ptr(0xD)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x5), wkv_add(&wkv, "a/d/5", i2ptr(0x5)));
    // there is no key "a/d/6", that node will be created implicitly without value.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), wkv_add(&wkv, "a/d/6/e", i2ptr(0xE)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0xF), wkv_add(&wkv, "a/d/6/f", i2ptr(0xF)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x101), wkv_add(&wkv, "a/d/6/1", i2ptr(0x101)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x102), wkv_add(&wkv, "a/d/6/2", i2ptr(0x102)));

    print(&wkv.root);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;

    // Query literal.
    char key_buf[WKV_KEY_MAX_LEN + 1];
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_STRING("a", collector.get_only().key.c_str());
        TEST_ASSERT_EQUAL_size_t(0, collector.get_only().substitutions.size());
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xA), collector.get_only().value);
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a1", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_STRING("a1", collector.get_only().key.c_str());
        TEST_ASSERT_EQUAL_size_t(0, collector.get_only().substitutions.size());
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xA1), collector.get_only().value);
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a2", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_STRING("a2", collector.get_only().key.c_str());
        TEST_ASSERT_EQUAL_size_t(0, collector.get_only().substitutions.size());
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xA2), collector.get_only().value);
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/d/6/e", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_STRING("a/d/6/e", collector.get_only().key.c_str());
        TEST_ASSERT_EQUAL_size_t(0, collector.get_only().substitutions.size());
        TEST_ASSERT_EQUAL_PTR(i2ptr(0xE), collector.get_only().value);
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/d/6/", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(0, collector.get_matches().size());
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(0, collector.get_matches().size());
    }

    // Query non-recursive substitution.
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(3, matches.size());
        TEST_ASSERT(matches[0].check("a", { "a" }, i2ptr(0xA)));
        TEST_ASSERT(matches[1].check("a1", { "a1" }, i2ptr(0xA1)));
        TEST_ASSERT(matches[2].check("a2", { "a2" }, i2ptr(0xA2)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/*", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(3, matches.size());
        TEST_ASSERT(matches[0].check("a/b", { "b" }, i2ptr(0xB)));
        TEST_ASSERT(matches[1].check("a/c", { "c" }, i2ptr(0xC)));
        TEST_ASSERT(matches[2].check("a/d", { "d" }, i2ptr(0xD)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*/b", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(2, matches.size());
        TEST_ASSERT(matches[0].check("a/b", { "a" }, i2ptr(0xB)));
        TEST_ASSERT(matches[1].check("x/b", { "x" }, i2ptr(0x100)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*/*/*", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(5, matches.size());
        TEST_ASSERT(matches[0].check("a/b/1", { "a", "b", "1" }, i2ptr(0x1)));
        TEST_ASSERT(matches[1].check("a/b/2", { "a", "b", "2" }, i2ptr(0x2)));
        TEST_ASSERT(matches[2].check("a/c/1", { "a", "c", "1" }, i2ptr(0x3)));
        TEST_ASSERT(matches[3].check("a/c/2", { "a", "c", "2" }, i2ptr(0x4)));
        TEST_ASSERT(matches[4].check("a/d/5", { "a", "d", "5" }, i2ptr(0x5)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*/c/*", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(2, matches.size());
        TEST_ASSERT(matches[0].check("a/c/1", { "a", "1" }, i2ptr(0x3)));
        TEST_ASSERT(matches[1].check("a/c/2", { "a", "2" }, i2ptr(0x4)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/*/2", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(2, matches.size());
        TEST_ASSERT(matches[0].check("a/b/2", { "b" }, i2ptr(0x2)));
        TEST_ASSERT(matches[1].check("a/c/2", { "c" }, i2ptr(0x4)));
    }

    // Query recursive substitution.
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/b/**", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(2, matches.size());
        TEST_ASSERT(matches[0].check("a/b/1", { "1" }, i2ptr(0x1)));
        TEST_ASSERT(matches[1].check("a/b/2", { "2" }, i2ptr(0x2)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/d/**", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(5, matches.size());
        TEST_ASSERT(matches[0].check("a/d/5", { "5" }, i2ptr(0x5)));
        TEST_ASSERT(matches[1].check("a/d/6/1", { "6", "1" }, i2ptr(0x101)));
        TEST_ASSERT(matches[2].check("a/d/6/2", { "6", "2" }, i2ptr(0x102)));
        TEST_ASSERT(matches[3].check("a/d/6/e", { "6", "e" }, i2ptr(0xE)));
        TEST_ASSERT(matches[4].check("a/d/6/f", { "6", "f" }, i2ptr(0xF)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(16, matches.size()); // everything is matched
        for (const auto& m : matches) {
            // std::cout << "Hit: " << m.key << " -> " << m.join_substitutions() << " = " << m.value << std::endl;
            TEST_ASSERT(m.value != nullptr);
            TEST_ASSERT(m.join_substitutions() == m.key);
        }
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/*/6/**", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(4, matches.size());
        TEST_ASSERT(matches[0].check("a/d/6/1", { "d", "1" }, i2ptr(0x101)));
        TEST_ASSERT(matches[1].check("a/d/6/2", { "d", "2" }, i2ptr(0x102)));
        TEST_ASSERT(matches[2].check("a/d/6/e", { "d", "e" }, i2ptr(0xE)));
        TEST_ASSERT(matches[3].check("a/d/6/f", { "d", "f" }, i2ptr(0xF)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/*/6/**", nullptr, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(4, matches.size());
        TEST_ASSERT(matches[0].check("", { "d", "1" }, i2ptr(0x101)));
        TEST_ASSERT(matches[1].check("", { "d", "2" }, i2ptr(0x102)));
        TEST_ASSERT(matches[2].check("", { "d", "e" }, i2ptr(0xE)));
        TEST_ASSERT(matches[3].check("", { "d", "f" }, i2ptr(0xF)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**/1", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(3, matches.size());
        TEST_ASSERT(matches[0].check("a/b/1", { "a", "b" }, i2ptr(0x1)));
        TEST_ASSERT(matches[1].check("a/c/1", { "a", "c" }, i2ptr(0x3)));
        TEST_ASSERT(matches[2].check("a/d/6/1", { "a", "d", "6" }, i2ptr(0x101)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/**/2", key_buf, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(3, matches.size());
        TEST_ASSERT(matches[0].check("a/b/2", { "b" }, i2ptr(0x2)));
        TEST_ASSERT(matches[1].check("a/c/2", { "c" }, i2ptr(0x4)));
        TEST_ASSERT(matches[2].check("a/d/6/2", { "d", "6" }, i2ptr(0x102)));
    }

    // Cleanup.
    while (!wkv_is_empty(&wkv)) {
        size_t      key_len = WKV_KEY_MAX_LEN + 1;
        void* const v       = wkv_at(&wkv, 0, key_buf, &key_len);
        TEST_ASSERT(nullptr != v);
        TEST_ASSERT(key_len <= WKV_KEY_MAX_LEN);
        TEST_ASSERT_EQUAL_PTR(v, wkv_set(&wkv, key_buf, nullptr));
    }
    TEST_ASSERT(wkv_is_empty(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_match_2()
{
    Memory mem(50);
    wkv_t  wkv     = wkv_init(Memory::trampoline);
    wkv.context    = &mem;
    const auto add = [&wkv](const char* const key, const auto value) {
        TEST_ASSERT_EQUAL_PTR(i2ptr(value), wkv_add(&wkv, key, i2ptr(value)));
    };

    // Populate the container.
    add("a/b/c/d", 0xABCD);
    add("a/b/c/d/b/c/d", 0xABCDBCD);
    add("a/b/d/b/c", 0xABDBC);
    add("a/b/d/b/c/", 0xABDBC0);
    add("a/b/d/b/c/d", 0xABDBCD);
    add("a/b/c/d/a/b/c/d", 0xABCDABCD);
    add("a/b/d/b/c/d/", 0xABDBCD0);
    add("a/f/c/d/b/c/d", 0xAFCDBCD);
    print(&wkv.root);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;
    char key_buf[WKV_KEY_MAX_LEN + 1];

    // Test.
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/**/d", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(5, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d", { "b", "c" }, i2ptr(0xABCD)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/a/b/c/d", { "b", "c", "d", "a", "b", "c" }, i2ptr(0xABCDABCD)));
        TEST_ASSERT(col.get_matches()[2].check("a/b/c/d/b/c/d", { "b", "c", "d", "b", "c" }, i2ptr(0xABCDBCD)));
        TEST_ASSERT(col.get_matches()[3].check("a/b/d/b/c/d", { "b", "d", "b", "c" }, i2ptr(0xABDBCD)));
        TEST_ASSERT(col.get_matches()[4].check("a/f/c/d/b/c/d", { "f", "c", "d", "b", "c" }, i2ptr(0xAFCDBCD)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/b/**/c/d", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d/a/b/c/d", { "c", "d", "a", "b" }, i2ptr(0xABCDABCD)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/b/c/d", { "c", "d", "b" }, i2ptr(0xABCDBCD)));
        TEST_ASSERT(col.get_matches()[2].check("a/b/d/b/c/d", { "d", "b" }, i2ptr(0xABDBCD)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/b/**/c/d", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d/a/b/c/d", { "c", "d", "a", "b" }, i2ptr(0xABCDABCD)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/b/c/d", { "c", "d", "b" }, i2ptr(0xABCDBCD)));
        TEST_ASSERT(col.get_matches()[2].check("a/b/d/b/c/d", { "d", "b" }, i2ptr(0xABDBCD)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "a/*/c/**/c/d", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d/a/b/c/d", { "b", "d", "a", "b" }, i2ptr(0xABCDABCD)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/b/c/d", { "b", "d", "b" }, i2ptr(0xABCDBCD)));
        TEST_ASSERT(col.get_matches()[2].check("a/f/c/d/b/c/d", { "f", "d", "b" }, i2ptr(0xAFCDBCD)));
    }
    {
        Collector col; // If more than one ** is present, the non-first ** is treated as *.
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**/c/**/c/d", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(0, col.get_matches().size());
    }
    {
        Collector col; // If more than one ** is present, the non-first ** is treated as *.
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**/c/d/**/c/d", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d/b/c/d", { "a", "b", "b" }, i2ptr(0xABCDBCD)));
        TEST_ASSERT(col.get_matches()[1].check("a/f/c/d/b/c/d", { "a", "f", "b" }, i2ptr(0xAFCDBCD)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**/", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/d/b/c/", { "a", "b", "d", "b", "c" }, i2ptr(0xABDBC0)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/d/b/c/d/", { "a", "b", "d", "b", "c", "d" }, i2ptr(0xABDBCD0)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*/**/", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/d/b/c/", { "a", "b", "d", "b", "c" }, i2ptr(0xABDBC0)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/d/b/c/d/", { "a", "b", "d", "b", "c", "d" }, i2ptr(0xABDBCD0)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**/*/", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/d/b/c/", { "a", "b", "d", "b", "c" }, i2ptr(0xABDBC0)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/d/b/c/d/", { "a", "b", "d", "b", "c", "d" }, i2ptr(0xABDBCD0)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*/**/*/", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/d/b/c/", { "a", "b", "d", "b", "c" }, i2ptr(0xABDBC0)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/d/b/c/d/", { "a", "b", "d", "b", "c", "d" }, i2ptr(0xABDBCD0)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*/*/**/*/", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/d/b/c/", { "a", "b", "d", "b", "c" }, i2ptr(0xABDBC0)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/d/b/c/d/", { "a", "b", "d", "b", "c", "d" }, i2ptr(0xABDBCD0)));
    }
    {
        Collector col; // If more than one ** is present, the non-first ** is treated as *.
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**/**/", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/d/b/c/", { "a", "b", "d", "b", "c" }, i2ptr(0xABDBC0)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/d/b/c/d/", { "a", "b", "d", "b", "c", "d" }, i2ptr(0xABDBCD0)));
    }
    {
        Collector col; // If more than one ** is present, the non-first ** is treated as *.
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*/**/**/", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/d/b/c/", { "a", "b", "d", "b", "c" }, i2ptr(0xABDBC0)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/d/b/c/d/", { "a", "b", "d", "b", "c", "d" }, i2ptr(0xABDBCD0)));
    }
    {
        Collector col; // If more than one ** is present, the non-first ** is treated as *.
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**/b/c/**", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(6, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d", { "a", "d" }, i2ptr(0xABCD)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/b/c/d", { "a", "b", "c", "d", "d" }, i2ptr(0xABCDBCD))); // sic!
        TEST_ASSERT(col.get_matches()[2].check("a/b/c/d/a/b/c/d", { "a", "b", "c", "d", "a", "d" }, i2ptr(0xABCDABCD)));
        TEST_ASSERT(col.get_matches()[3].check("a/b/d/b/c/", { "a", "b", "d", "" }, i2ptr(0xABDBC0)));
        TEST_ASSERT(col.get_matches()[4].check("a/b/d/b/c/d", { "a", "b", "d", "d" }, i2ptr(0xABDBCD)));
        TEST_ASSERT(col.get_matches()[5].check("a/f/c/d/b/c/d", { "a", "f", "c", "d", "d" }, i2ptr(0xAFCDBCD)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "*/b/c/**", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d", { "a", "d" }, i2ptr(0xABCD)));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/a/b/c/d", { "a", "d", "a", "b", "c", "d" }, i2ptr(0xABCDABCD)));
        TEST_ASSERT(col.get_matches()[2].check("a/b/c/d/b/c/d", { "a", "d", "b", "c", "d" }, i2ptr(0xABCDBCD)));
    }

    // Cleanup.
    while (!wkv_is_empty(&wkv)) {
        size_t      key_len = WKV_KEY_MAX_LEN + 1;
        void* const v       = wkv_at(&wkv, 0, key_buf, &key_len);
        TEST_ASSERT(nullptr != v);
        TEST_ASSERT(key_len <= WKV_KEY_MAX_LEN);
        TEST_ASSERT_EQUAL_PTR(v, wkv_set(&wkv, key_buf, nullptr));
    }
    TEST_ASSERT(wkv_is_empty(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_match_3()
{
    Memory mem(50);
    wkv_t  wkv     = wkv_init(Memory::trampoline);
    wkv.context    = &mem;
    const auto add = [&wkv](const char* const key, const auto value) {
        TEST_ASSERT_EQUAL_PTR(i2ptr(value), wkv_add(&wkv, key, i2ptr(value)));
    };
    add("", 0x01);
    add("/", 0x02);
    char key_buf[WKV_KEY_MAX_LEN + 1];

    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**/", key_buf, &col, Collector::trampoline));
        TEST_ASSERT(col.get_only().check("/", { "" }, i2ptr(0x02)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "/**", key_buf, &col, Collector::trampoline));
        TEST_ASSERT(col.get_only().check("/", { "" }, i2ptr(0x02)));
    }
    {
        Collector col;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_match(&wkv, "**", key_buf, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("", { "" }, i2ptr(0x01)));
        TEST_ASSERT(col.get_matches()[1].check("/", { "", "" }, i2ptr(0x02)));
    }

    // Cleanup.
    (void)wkv_set(&wkv, "", nullptr);
    (void)wkv_set(&wkv, "/", nullptr);
    TEST_ASSERT(wkv_is_empty(&wkv));
}

void test_route()
{
    Memory mem(50);
    wkv_t  wkv  = wkv_init(Memory::trampoline);
    wkv.context = &mem;

    // Insert some patterns.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x01), wkv_add(&wkv, "", i2ptr(0x01)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x02), wkv_add(&wkv, "/", i2ptr(0x02)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x03), wkv_add(&wkv, "a/b/c", i2ptr(0x03)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x04), wkv_add(&wkv, "a/*/c", i2ptr(0x04)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x05), wkv_add(&wkv, "*/b/*", i2ptr(0x05)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x06), wkv_add(&wkv, "a/b/c/", i2ptr(0x06)));
    print(&wkv.root);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;
    char key_buf[WKV_KEY_MAX_LEN + 1];

    // Test some keys.
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("", {}, i2ptr(0x01)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "/", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("/", {}, i2ptr(0x02)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "a/b", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_matches().empty());
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "a/b/c/", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("a/b/c/", {}, i2ptr(0x06)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "a/b/c", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("*/b/*", { "a", "c" }, i2ptr(0x05)));
        TEST_ASSERT(collector.get_matches()[1].check("a/*/c", { "b" }, i2ptr(0x04)));
        TEST_ASSERT(collector.get_matches()[2].check("a/b/c", {}, i2ptr(0x03)));
    }

    // Add more patterns.
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x07), wkv_add(&wkv, "**", i2ptr(0x07)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x08), wkv_add(&wkv, "**/", i2ptr(0x08)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x09), wkv_add(&wkv, "a/**", i2ptr(0x09)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x0A), wkv_add(&wkv, "**/c/*", i2ptr(0x0A)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x0B), wkv_add(&wkv, "**/b/**", i2ptr(0x0B))); // second ** is treated as *

    // Test same keys, get different results.
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_matches()[0].check("**", { "" }, i2ptr(0x07)));
        TEST_ASSERT(collector.get_matches()[1].check("", {}, i2ptr(0x01)));
        TEST_ASSERT_EQUAL_size_t(2, collector.get_matches().size());
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "/", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_matches()[0].check("**/", { "" }, i2ptr(0x08)));
        TEST_ASSERT(collector.get_matches()[1].check("**", { "", "" }, i2ptr(0x07)));
        TEST_ASSERT(collector.get_matches()[2].check("/", {}, i2ptr(0x02)));
        TEST_ASSERT_EQUAL_size_t(3, collector.get_matches().size());
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "a/b", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("**", { "a", "b" }, i2ptr(0x07)));
        TEST_ASSERT(collector.get_matches()[1].check("a/**", { "b" }, i2ptr(0x09)));
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "a/b/c/", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(5, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("**/c/*", { "a", "b", "" }, i2ptr(0x0A)));
        TEST_ASSERT(collector.get_matches()[1].check("**/", { "a", "b", "c" }, i2ptr(0x08)));
        TEST_ASSERT(collector.get_matches()[2].check("**", { "a", "b", "c", "" }, i2ptr(0x07)));
        TEST_ASSERT(collector.get_matches()[3].check("a/**", { "b", "c", "" }, i2ptr(0x09)));
        TEST_ASSERT(collector.get_matches()[4].check("a/b/c/", {}, i2ptr(0x06)));
        // NB! "**/b/**" did not match because the second ** is treated as *.
    }
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "a/b/c", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(6, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("*/b/*", { "a", "c" }, i2ptr(0x05)));
        TEST_ASSERT(collector.get_matches()[1].check("**/b/**", { "a", "c" }, i2ptr(0x0B)));
        TEST_ASSERT(collector.get_matches()[2].check("**", { "a", "b", "c" }, i2ptr(0x07)));
        TEST_ASSERT(collector.get_matches()[3].check("a/*/c", { "b" }, i2ptr(0x04)));
        TEST_ASSERT(collector.get_matches()[4].check("a/**", { "b", "c" }, i2ptr(0x09)));
        TEST_ASSERT(collector.get_matches()[5].check("a/b/c", {}, i2ptr(0x03)));
    }

    // Cleanup.
    while (!wkv_is_empty(&wkv)) {
        size_t      key_len = WKV_KEY_MAX_LEN + 1;
        void* const v       = wkv_at(&wkv, 0, key_buf, &key_len);
        TEST_ASSERT(nullptr != v);
        TEST_ASSERT(key_len <= WKV_KEY_MAX_LEN);
        TEST_ASSERT_EQUAL_PTR(v, wkv_set(&wkv, key_buf, nullptr));
    }
    TEST_ASSERT(wkv_is_empty(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, count(&wkv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_route_2()
{
    Memory mem(50);
    wkv_t  wkv  = wkv_init(Memory::trampoline);
    wkv.context = &mem;
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x01), wkv_add(&wkv, "x", i2ptr(0x01)));
    TEST_ASSERT_EQUAL_PTR(i2ptr(0x02), wkv_add(&wkv, "**/x", i2ptr(0x02)));
    char key_buf[WKV_KEY_MAX_LEN + 1];
    {
        Collector collector;
        TEST_ASSERT_EQUAL_PTR(nullptr, wkv_route(&wkv, "a/x", key_buf, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("**/x", { "a" }, i2ptr(0x02)));
    }
    // Cleanup.
    while (!wkv_is_empty(&wkv)) {
        size_t      key_len = WKV_KEY_MAX_LEN + 1;
        void* const v       = wkv_at(&wkv, 0, key_buf, &key_len);
        TEST_ASSERT(nullptr != v);
        TEST_ASSERT(key_len <= WKV_KEY_MAX_LEN);
        TEST_ASSERT_EQUAL_PTR(v, wkv_set(&wkv, key_buf, nullptr));
    }
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
    RUN_TEST(test_reconstruct);
    RUN_TEST(test_match);
    RUN_TEST(test_match_2);
    RUN_TEST(test_match_3);
    RUN_TEST(test_route);
    RUN_TEST(test_route_2);
    return UNITY_END();
    // NOLINTEND(misc-include-cleaner)
}
