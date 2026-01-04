/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#include "wkv.h"
#include <unity.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <algorithm>
#include <ranges>
#include <string_view>
#include <string>
#include <vector>
#include <unordered_set>
#include <utility>
#include <stdexcept>
#include <optional>
#include <functional>

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
            // When realloc fails, the original pointer remains valid per standard semantics.
            // WKV will free it later with new_size == 0.
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

::wkv_str_t operator""_wkv(const char* v, const std::size_t sz)
{
    return {sz, v};
}

class Collector final
{
public:
    struct Hit
    {
        std::string                                      key;
        std::vector<std::pair<std::size_t, std::string>> substitutions;
        void*                                            value = nullptr;

        explicit Hit(::wkv_node_t* const               node,
                     const std::string_view            key,
                     const std::size_t                 sub_count,
                     const ::wkv_substitution_t* const subs)
          : key(key)
          , value(node->value)
        {
            const ::wkv_substitution_t* s = subs;
            substitutions.reserve(sub_count);
            while (s != nullptr) {
                substitutions.emplace_back(s->ordinal, view(s->str));
                s = s->next;
            }
            TEST_ASSERT_EQUAL_size_t(sub_count, substitutions.size());
        }

        [[nodiscard]] bool check(const std::string_view                                  key,
                                 const std::vector<std::pair<std::size_t, std::string>>& substitutions,
                                 const char* const                                       value) const
        {
            return (this->key == key) && (this->substitutions.size() == substitutions.size()) &&
                   std::equal(this->substitutions.begin(), this->substitutions.end(), substitutions.begin()) &&
                   (std::string_view(static_cast<const char*>(this->value)) == value);
        }

        [[nodiscard]] std::string join_substitutions(const std::string_view sep = "/") const
        {
            std::string result;
            for (const auto& val : substitutions | std::views::values) {
                if (!result.empty()) {
                    result += sep;
                }
                result += val;
            }
            return result;
        }

        [[nodiscard]] std::string substitutions_to_string() const
        {
            std::string result;
            for (const auto& s : substitutions) {
                if (!result.empty()) {
                    result += " ";
                }
                result += "#" + std::to_string(s.first) + ":" + s.second;
            }
            return result;
        }
    };

    explicit Collector() = default;
    explicit Collector(const std::function<void*(const Hit&)>& done_predicate) : done_predicate_(done_predicate) {}

    [[nodiscard]] const std::vector<Hit>& get_matches() const { return matches_; }

    [[nodiscard]] const Hit& get_only() const
    {
        TEST_ASSERT_EQUAL_size_t(1, matches_.size());
        return matches_.front();
    }

    [[nodiscard]] static void* trampoline(const ::wkv_event_t event)
    {
        return static_cast<Collector*>(event.context)->on_hit(event);
    }

    [[maybe_unused]] void print() const
    {
        std::cout << matches_.size() << " matches:" << std::endl;
        for (const auto& match : matches_) {
            std::cout << "'" << match.key << "' --> " << match.value << "; {" << match.substitutions_to_string() << "}"
                      << std::endl;
        }
    }

private:
    [[nodiscard]] void* on_hit(const ::wkv_event_t event)
    {
        std::string key(event.node->key_len, '\0');
        wkv_get_key(event.self, event.node, key.data());
        matches_.emplace_back(event.node, key, event.substitution_count, event.substitutions);
        return done_predicate_(matches_.back());
    }

    std::vector<Hit>                       matches_;
    const std::function<void*(const Hit&)> done_predicate_ = [](const Hit&) { return nullptr; };
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
void print(const ::wkv_t* const kv)
{
    print(&kv->root);
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

wkv_str_t wkv_key(const std::string_view str)
{
    return {str.length(), str.data()};
}

class WildKV final : public ::wkv_t
{
public:
    explicit WildKV(Memory& mem) : ::wkv_t{}
    {
        ::wkv_init(this, Memory::trampoline);
        this->context = &mem;
        TEST_ASSERT(empty());
    }

    [[nodiscard]] bool empty() const noexcept { return ::wkv_is_empty(this); }

    [[nodiscard]] std::size_t count() const noexcept { return ::count(this); }

    [[nodiscard]] std::string key(const ::wkv_node_t* const node) const
    {
        std::string key(node->key_len, '\0');
        ::wkv_get_key(this, node, key.data());
        return key;
    }

    void purge()
    {
        while (!::wkv_is_empty(this)) {
            ::wkv_del(this, ::wkv_at(this, 0));
        }
        TEST_ASSERT_EQUAL_size_t(0, count());
    }

    template<typename Owner>
    class Proxy final
    {
    public:
        Proxy(Owner* const owner, const std::string_view key) : owner_(owner), key_(key) {}

        Proxy& operator=(const char* const value) &&
        {
            if (value == nullptr) {
                throw std::range_error("Cannot assign nullptr");
            }
            ::wkv_node_t* const node = ::wkv_set(owner_, wkv_key(key_));
            if (node == nullptr) {
                throw std::bad_alloc();
            }
            node->value = const_cast<char*>(value); // NOLINT(*-const-cast)
            return *this;
        }

        [[nodiscard]] bool add(const char* const value) && noexcept
        {
            ::wkv_node_t* const node = ::wkv_set(owner_, wkv_key(key_));
            if (node != nullptr) {
                node->value = const_cast<char*>(value); // NOLINT(*-const-cast)
                return true;
            }
            return false;
        }

        [[nodiscard]] explicit(false) operator const char*() const&& noexcept // NOLINT(*-explicit-*)
        {
            const ::wkv_node_t* const node = ::wkv_get(owner_, wkv_key(key_));
            if (node == nullptr) {
                return nullptr;
            }
            return static_cast<const char*>(node->value);
        }
        [[nodiscard]] explicit(false) operator bool() const noexcept // NOLINT(*-explicit-*)
        {
            return ::wkv_get(owner_, wkv_key(key_)) != nullptr;
        }

        void erase() && noexcept
        {
            const std::size_t cold = ::count(owner_);
            TEST_ASSERT(cold > 0);
            ::wkv_del(owner_, ::wkv_get(owner_, wkv_key(key_)));
            TEST_ASSERT_EQUAL_size_t(cold - 1, ::count(owner_));
        }

    private:
        Owner* const           owner_;
        const std::string_view key_;
    };

    [[nodiscard]] Proxy<WildKV>       operator[](const std::string_view key) { return {this, key}; }
    [[nodiscard]] Proxy<const WildKV> operator[](const std::string_view key) const { return {this, key}; }

    class IndexProxy final
    {
    public:
        IndexProxy(const WildKV* const owner, const ::wkv_node_t* const node) : owner_(owner), node_(node) {}
        [[nodiscard]] explicit(false) operator bool() const noexcept // NOLINT(*-explicit-*)
        {
            return node_ != nullptr;
        }
        [[nodiscard]] std::optional<std::string> key() const
        {
            if (node_ != nullptr) {
                return owner_->key(node_);
            }
            return std::nullopt;
        }
        [[nodiscard]] const char* value() const noexcept { return static_cast<const char*>(node_->value); }

    private:
        const WildKV* const       owner_;
        const ::wkv_node_t* const node_;
    };
    [[nodiscard]] IndexProxy operator[](const std::size_t index) { return IndexProxy(this, ::wkv_at(this, index)); }
};

void test_basic()
{
    Memory mem(18);
    WildKV kv(mem);

    // Insert some keys and check the count.
    kv["foo"]          = "a";
    kv["/foo/"]        = "b";
    kv["//foo//"]      = "c";
    kv["/foo/bar"]     = "d";
    kv["/foo/bar/"]    = "e";
    kv["/foo/bar/baz"] = "f";
    kv[""]             = "empty";
    TEST_ASSERT_EQUAL_size_t(7, kv.count());
    kv["/foo/bar/"] = "1"; // existing reassignment
    TEST_ASSERT_EQUAL_size_t(7, kv.count());
    TEST_ASSERT(!kv.empty());
    print(&kv);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;

    // Get some keys.
    TEST_ASSERT_EQUAL_STRING("a", kv["foo"]);
    TEST_ASSERT_EQUAL_STRING("b", kv["/foo/"]);
    TEST_ASSERT_EQUAL_STRING("c", kv["//foo//"]);
    TEST_ASSERT_EQUAL_STRING("d", kv["/foo/bar"]);
    TEST_ASSERT_EQUAL_STRING("1", kv["/foo/bar/"]);
    TEST_ASSERT_EQUAL_STRING("f", kv["/foo/bar/baz"]);
    TEST_ASSERT_EQUAL_STRING("empty", kv[""]);

    TEST_ASSERT_FALSE(kv["nonexistent"]);
    TEST_ASSERT_FALSE(kv["foo/"]);
    TEST_ASSERT_FALSE(kv["/foo"]);
    TEST_ASSERT_FALSE(kv["//foo"]);
    TEST_ASSERT_FALSE(kv["/foo//"]);
    TEST_ASSERT_FALSE(kv["/nonexistent/"]);
    TEST_ASSERT_FALSE(kv["//nonexistent//"]);

    // Check indexing. Simply iterate until we get all keys and ensure that each occurred exactly once.
    {
        const size_t                    expected_count = count(&kv);
        std::unordered_set<std::string> keys{"foo", "/foo/", "//foo//", "/foo/bar", "/foo/bar/", "/foo/bar/baz", ""};
        for (size_t i = 0; i < expected_count; ++i) {
            TEST_ASSERT(kv[i]);
            const std::string key = kv[i].key().value();
            TEST_ASSERT_EQUAL_size_t(1, keys.erase(key));
            // compare against the reference
            TEST_ASSERT_EQUAL_STRING(kv[i].value(), kv[key]);
        }
        TEST_ASSERT_EQUAL_size_t(0, keys.size());
        TEST_ASSERT_FALSE(kv[expected_count]);
        TEST_ASSERT_FALSE(kv[100]);
    }

    // Delete some keys.
    kv["foo"].erase();
    TEST_ASSERT_FALSE(kv["foo"]);
    TEST_ASSERT_EQUAL_size_t(6, count(&kv));
    kv["/foo/"].erase();
    kv["//foo//"].erase();
    kv["/foo/bar"].erase();
    kv["/foo/bar/"].erase();
    kv["/foo/bar/baz"].erase();
    kv[""].erase();
    TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    TEST_ASSERT(kv.empty());

    // Edge cases.
    wkv_del(&kv, nullptr);
    wkv_del(&kv, &kv.root); // no effect
}

void test_backtrack()
{
    {
        Memory mem(0);
        WildKV kv(mem);
        TEST_ASSERT_NULL(wkv_set(&kv, wkv_key("a")));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    }
    {
        Memory mem(1);
        WildKV kv(mem);
        TEST_ASSERT_NULL(wkv_set(&kv, wkv_key("a")));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(1, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    }
    {
        Memory mem(1);
        WildKV kv(mem);
        TEST_ASSERT_NULL(wkv_set(&kv, wkv_key("a/b")));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(1, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    }
    {
        Memory mem(2);
        WildKV kv(mem);
        TEST_ASSERT_NULL(wkv_set(&kv, wkv_key("a/b")));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(0, count(&kv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(3);
        WildKV kv(mem);
        TEST_ASSERT_NULL(wkv_set(&kv, wkv_key("a/b")));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(3, mem.get_fragments_peak());
        TEST_ASSERT(wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(0, count(&kv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(3); // top node A will be retained because it has a payload.
        WildKV kv(mem);
        kv["a"] = "x";
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments_peak());
        TEST_ASSERT_FALSE(kv["a/b"].add("y"));
        TEST_ASSERT_EQUAL_size_t(2, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(3, mem.get_fragments_peak());
        TEST_ASSERT(!wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(1, count(&kv));
        // cleanup
        wkv_del(&kv, wkv_get(&kv, wkv_key("a")));
        TEST_ASSERT(wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(0, count(&kv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
    {
        Memory mem(4); // top node A will be retained because it has a child.
        WildKV kv(mem);
        kv["a/b"] = "x";
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments_peak());
        TEST_ASSERT_FALSE(kv["a/c"].add("y"));
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments());
        TEST_ASSERT_EQUAL_size_t(4, mem.get_fragments_peak());
        TEST_ASSERT(!wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(1, count(&kv));
        // cleanup
        wkv_del(&kv, wkv_get(&kv, wkv_key("a/b")));
        TEST_ASSERT(wkv_is_empty(&kv));
        TEST_ASSERT_EQUAL_size_t(0, count(&kv));
        TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
    }
}

void test_reconstruct()
{
    Memory mem(50);
    WildKV kv(mem);

    kv["xx/a"]    = "A";
    kv["xx//b"]   = "B";
    kv[""]        = "C";
    kv["/"]       = "D";
    kv["e"]       = "E";
    kv["/xx//f/"] = "F";
    kv["//"]      = "1";

    char buf[1000];

    const ::wkv_node_t* n = wkv_get(&kv, {4, "xx/a"});
    TEST_ASSERT_EQUAL_STRING("A", n->value);
    wkv_get_key(&kv, n, buf);
    TEST_ASSERT_EQUAL_STRING("xx/a", buf);

    n = wkv_get(&kv, {5, "xx//b"});
    TEST_ASSERT_EQUAL_STRING("B", n->value);
    wkv_get_key(&kv, n, buf);
    TEST_ASSERT_EQUAL_STRING("xx//b", buf);

    n = wkv_get(&kv, {0, ""});
    TEST_ASSERT_EQUAL_STRING("C", n->value);
    wkv_get_key(&kv, n, buf);
    TEST_ASSERT_EQUAL_STRING("", buf);

    n = wkv_get(&kv, {1, "/"});
    TEST_ASSERT_EQUAL_STRING("D", n->value);
    wkv_get_key(&kv, n, buf);
    TEST_ASSERT_EQUAL_STRING("/", buf);

    n = wkv_get(&kv, {1, "e"});
    TEST_ASSERT_EQUAL_STRING("E", n->value);
    wkv_get_key(&kv, n, buf);
    TEST_ASSERT_EQUAL_STRING("e", buf);

    n = wkv_get(&kv, {7, "/xx//f/"});
    TEST_ASSERT_EQUAL_STRING("F", n->value);
    wkv_get_key(&kv, n, buf);
    TEST_ASSERT_EQUAL_STRING("/xx//f/", buf);

    n = wkv_get(&kv, {2, "//"});
    TEST_ASSERT_EQUAL_STRING("1", n->value);
    wkv_get_key(&kv, n, buf);
    TEST_ASSERT_EQUAL_STRING("//", buf);

    kv.purge();
    TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_match()
{
    Memory mem(25);
    WildKV kv(mem);

    // Insert some keys.
    kv["a1"] = "x1";
    kv["a2"] = "x2";
    kv["a"]  = "A";

    kv["a/b"]   = "B";
    kv["a/b/1"] = "1";
    kv["a/b/2"] = "2";
    kv["x/b"]   = "100";

    kv["a/c"]   = "C";
    kv["a/c/1"] = "3";
    kv["a/c/2"] = "4";

    kv["a/d"]   = "D";
    kv["a/d/5"] = "5";
    // there is no key "a/d/6", that node will be created implicitly without value.
    kv["a/d/6/e"] = "E";
    kv["a/d/6/f"] = "F";
    kv["a/d/6/1"] = "101";
    kv["a/d/6/2"] = "102";

    print(&kv.root);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;

    // Query literal.
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_STRING("a", collector.get_only().key.c_str());
        TEST_ASSERT_EQUAL_size_t(0, collector.get_only().substitutions.size());
        TEST_ASSERT_EQUAL_STRING("A", collector.get_only().value);
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a1"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_STRING("a1", collector.get_only().key.c_str());
        TEST_ASSERT_EQUAL_size_t(0, collector.get_only().substitutions.size());
        TEST_ASSERT_EQUAL_STRING("x1", collector.get_only().value);
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a2"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_STRING("a2", collector.get_only().key.c_str());
        TEST_ASSERT_EQUAL_size_t(0, collector.get_only().substitutions.size());
        TEST_ASSERT_EQUAL_STRING("x2", collector.get_only().value);
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/d/6/e"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_STRING("a/d/6/e", collector.get_only().key.c_str());
        TEST_ASSERT_EQUAL_size_t(0, collector.get_only().substitutions.size());
        TEST_ASSERT_EQUAL_STRING("E", collector.get_only().value);
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/d/6/"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(0, collector.get_matches().size());
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, ""_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(0, collector.get_matches().size());
    }

    // Query non-recursive substitution.
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "?"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(3, matches.size());
        TEST_ASSERT(matches[0].check("a", {{0, "a"}}, "A"));
        TEST_ASSERT(matches[1].check("a1", {{0, "a1"}}, "x1"));
        TEST_ASSERT(matches[2].check("a2", {{0, "a2"}}, "x2"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/?"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(3, matches.size());
        TEST_ASSERT(matches[0].check("a/b", {{0, "b"}}, "B"));
        TEST_ASSERT(matches[1].check("a/c", {{0, "c"}}, "C"));
        TEST_ASSERT(matches[2].check("a/d", {{0, "d"}}, "D"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "?/b"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(2, matches.size());
        TEST_ASSERT(matches[0].check("a/b", {{0, "a"}}, "B"));
        TEST_ASSERT(matches[1].check("x/b", {{0, "x"}}, "100"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "?/?/?"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(5, matches.size());
        TEST_ASSERT(matches[0].check("a/b/1", {{0, "a"}, {1, "b"}, {2, "1"}}, "1"));
        TEST_ASSERT(matches[1].check("a/b/2", {{0, "a"}, {1, "b"}, {2, "2"}}, "2"));
        TEST_ASSERT(matches[2].check("a/c/1", {{0, "a"}, {1, "c"}, {2, "1"}}, "3"));
        TEST_ASSERT(matches[3].check("a/c/2", {{0, "a"}, {1, "c"}, {2, "2"}}, "4"));
        TEST_ASSERT(matches[4].check("a/d/5", {{0, "a"}, {1, "d"}, {2, "5"}}, "5"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "?/c/?"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(2, matches.size());
        TEST_ASSERT(matches[0].check("a/c/1", {{0, "a"}, {1, "1"}}, "3"));
        TEST_ASSERT(matches[1].check("a/c/2", {{0, "a"}, {1, "2"}}, "4"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/?/2"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(2, matches.size());
        TEST_ASSERT(matches[0].check("a/b/2", {{0, "b"}}, "2"));
        TEST_ASSERT(matches[1].check("a/c/2", {{0, "c"}}, "4"));
    }

    // Query recursive substitution.
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/b/*"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(2, matches.size());
        TEST_ASSERT(matches[0].check("a/b/1", {{0, "1"}}, "1"));
        TEST_ASSERT(matches[1].check("a/b/2", {{0, "2"}}, "2"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/d/*"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(5, matches.size());
        TEST_ASSERT(matches[0].check("a/d/5", {{0, "5"}}, "5"));
        TEST_ASSERT(matches[1].check("a/d/6/1", {{0, "6"}, {0, "1"}}, "101"));
        TEST_ASSERT(matches[2].check("a/d/6/2", {{0, "6"}, {0, "2"}}, "102"));
        TEST_ASSERT(matches[3].check("a/d/6/e", {{0, "6"}, {0, "e"}}, "E"));
        TEST_ASSERT(matches[4].check("a/d/6/f", {{0, "6"}, {0, "f"}}, "F"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "*"_wkv, &collector, Collector::trampoline));
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
        TEST_ASSERT_NULL(wkv_match(&kv, "a/?/6/*"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(4, matches.size());
        TEST_ASSERT(matches[0].check("a/d/6/1", {{0, "d"}, {1, "1"}}, "101"));
        TEST_ASSERT(matches[1].check("a/d/6/2", {{0, "d"}, {1, "2"}}, "102"));
        TEST_ASSERT(matches[2].check("a/d/6/e", {{0, "d"}, {1, "e"}}, "E"));
        TEST_ASSERT(matches[3].check("a/d/6/f", {{0, "d"}, {1, "f"}}, "F"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/?/6/*"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(4, matches.size());
        TEST_ASSERT(matches[0].check("a/d/6/1", {{0, "d"}, {1, "1"}}, "101"));
        TEST_ASSERT(matches[1].check("a/d/6/2", {{0, "d"}, {1, "2"}}, "102"));
        TEST_ASSERT(matches[2].check("a/d/6/e", {{0, "d"}, {1, "e"}}, "E"));
        TEST_ASSERT(matches[3].check("a/d/6/f", {{0, "d"}, {1, "f"}}, "F"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "*/1"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(3, matches.size());
        TEST_ASSERT(matches[0].check("a/b/1", {{0, "a"}, {0, "b"}}, "1"));
        TEST_ASSERT(matches[1].check("a/c/1", {{0, "a"}, {0, "c"}}, "3"));
        TEST_ASSERT(matches[2].check("a/d/6/1", {{0, "a"}, {0, "d"}, {0, "6"}}, "101"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/*/2"_wkv, &collector, Collector::trampoline));
        const auto& matches = collector.get_matches();
        TEST_ASSERT_EQUAL_size_t(3, matches.size());
        TEST_ASSERT(matches[0].check("a/b/2", {{0, "b"}}, "2"));
        TEST_ASSERT(matches[1].check("a/c/2", {{0, "c"}}, "4"));
        TEST_ASSERT(matches[2].check("a/d/6/2", {{0, "d"}, {0, "6"}}, "102"));
    }

    kv.purge();
    TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_match_2()
{
    Memory mem(50);
    WildKV kv(mem);

    // Populate the container.
    kv["a/b/c/d"]         = "ABCD";
    kv["a/b/c/d/b/c/d"]   = "ABCDBCD";
    kv["a/b/d/b/c"]       = "ABDBC";
    kv["a/b/d/b/c/"]      = "ABDBC0";
    kv["a/b/d/b/c/d"]     = "ABDBCD";
    kv["a/b/c/d/a/b/c/d"] = "ABCDABCD";
    kv["a/b/d/b/c/d/"]    = "ABDBCD0";
    kv["a/f/c/d/b/c/d"]   = "AFCDBCD";
    kv["a/f/c/d/*/c/d"]   = "AFCD0CD";
    print(&kv.root);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;

    // Test.
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/*/d"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(6, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d", {{0, "b"}, {0, "c"}}, "ABCD"));
        TEST_ASSERT(col.get_matches()[1].check(
          "a/b/c/d/a/b/c/d", {{0, "b"}, {0, "c"}, {0, "d"}, {0, "a"}, {0, "b"}, {0, "c"}}, "ABCDABCD"));
        TEST_ASSERT(
          col.get_matches()[2].check("a/b/c/d/b/c/d", {{0, "b"}, {0, "c"}, {0, "d"}, {0, "b"}, {0, "c"}}, "ABCDBCD"));
        TEST_ASSERT(col.get_matches()[3].check("a/b/d/b/c/d", {{0, "b"}, {0, "d"}, {0, "b"}, {0, "c"}}, "ABDBCD"));
        TEST_ASSERT(
          col.get_matches()[4].check("a/f/c/d/*/c/d", {{0, "f"}, {0, "c"}, {0, "d"}, {0, "*"}, {0, "c"}}, "AFCD0CD"));
        TEST_ASSERT(
          col.get_matches()[5].check("a/f/c/d/b/c/d", {{0, "f"}, {0, "c"}, {0, "d"}, {0, "b"}, {0, "c"}}, "AFCDBCD"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/b/?/*/c/d"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, col.get_matches().size());
        TEST_ASSERT(
          col.get_matches()[0].check("a/b/c/d/a/b/c/d", {{0, "c"}, {1, "d"}, {1, "a"}, {1, "b"}}, "ABCDABCD"));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/b/c/d", {{0, "c"}, {1, "d"}, {1, "b"}}, "ABCDBCD"));
        TEST_ASSERT(col.get_matches()[2].check("a/b/d/b/c/d", {{0, "d"}, {1, "b"}}, "ABDBCD"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/b/?/*/c/d"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, col.get_matches().size());
        TEST_ASSERT(
          col.get_matches()[0].check("a/b/c/d/a/b/c/d", {{0, "c"}, {1, "d"}, {1, "a"}, {1, "b"}}, "ABCDABCD"));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/b/c/d", {{0, "c"}, {1, "d"}, {1, "b"}}, "ABCDBCD"));
        TEST_ASSERT(col.get_matches()[2].check("a/b/d/b/c/d", {{0, "d"}, {1, "b"}}, "ABDBCD"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/?/c/?/*/c/d"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(4, col.get_matches().size());
        TEST_ASSERT(
          col.get_matches()[0].check("a/b/c/d/a/b/c/d", {{0, "b"}, {1, "d"}, {2, "a"}, {2, "b"}}, "ABCDABCD"));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/d/b/c/d", {{0, "b"}, {1, "d"}, {2, "b"}}, "ABCDBCD"));
        TEST_ASSERT(col.get_matches()[2].check("a/f/c/d/*/c/d", {{0, "f"}, {1, "d"}, {2, "*"}}, "AFCD0CD"));
        TEST_ASSERT(col.get_matches()[3].check("a/f/c/d/b/c/d", {{0, "f"}, {1, "d"}, {2, "b"}}, "AFCDBCD"));
    }
    {
        Collector col; // If more than one * is present, the non-first * is treated verbatim.
        TEST_ASSERT_NULL(wkv_match(&kv, "?/*/c/*/c/d"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(0, col.get_matches().size());
    }
    {
        Collector col; // If more than one * is present, the non-first * is treated verbatim.
        TEST_ASSERT_NULL(wkv_match(&kv, "?/*/c/d/*/c/d"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(1, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/f/c/d/*/c/d", {{0, "a"}, {1, "f"}}, "AFCD0CD"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "*/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(
          col.get_matches()[0].check("a/b/d/b/c/", {{0, "a"}, {0, "b"}, {0, "d"}, {0, "b"}, {0, "c"}}, "ABDBC0"));
        TEST_ASSERT(col.get_matches()[1].check(
          "a/b/d/b/c/d/", {{0, "a"}, {0, "b"}, {0, "d"}, {0, "b"}, {0, "c"}, {0, "d"}}, "ABDBCD0"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "?/*/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(
          col.get_matches()[0].check("a/b/d/b/c/", {{0, "a"}, {1, "b"}, {1, "d"}, {1, "b"}, {1, "c"}}, "ABDBC0"));
        TEST_ASSERT(col.get_matches()[1].check(
          "a/b/d/b/c/d/", {{0, "a"}, {1, "b"}, {1, "d"}, {1, "b"}, {1, "c"}, {1, "d"}}, "ABDBCD0"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "*/?/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(
          col.get_matches()[0].check("a/b/d/b/c/", {{0, "a"}, {0, "b"}, {0, "d"}, {0, "b"}, {1, "c"}}, "ABDBC0"));
        TEST_ASSERT(col.get_matches()[1].check(
          "a/b/d/b/c/d/", {{0, "a"}, {0, "b"}, {0, "d"}, {0, "b"}, {0, "c"}, {1, "d"}}, "ABDBCD0"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "?/*/?/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(
          col.get_matches()[0].check("a/b/d/b/c/", {{0, "a"}, {1, "b"}, {1, "d"}, {1, "b"}, {2, "c"}}, "ABDBC0"));
        TEST_ASSERT(col.get_matches()[1].check(
          "a/b/d/b/c/d/", {{0, "a"}, {1, "b"}, {1, "d"}, {1, "b"}, {1, "c"}, {2, "d"}}, "ABDBCD0"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "?/?/*/?/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(
          col.get_matches()[0].check("a/b/d/b/c/", {{0, "a"}, {1, "b"}, {2, "d"}, {2, "b"}, {3, "c"}}, "ABDBC0"));
        TEST_ASSERT(col.get_matches()[1].check(
          "a/b/d/b/c/d/", {{0, "a"}, {1, "b"}, {2, "d"}, {2, "b"}, {2, "c"}, {3, "d"}}, "ABDBCD0"));
    }
    {
        Collector col; // If more than one * is present, the non-first * is treated verbatim.
        TEST_ASSERT_NULL(wkv_match(&kv, "*/*/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(0, col.get_matches().size());
    }
    {
        Collector col; // If more than one * is present, the non-first * is treated verbatim.
        TEST_ASSERT_NULL(wkv_match(&kv, "?/*/*/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(0, col.get_matches().size());
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "?/b/c/*"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/c/d", {{0, "a"}, {1, "d"}}, "ABCD"));
        TEST_ASSERT(col.get_matches()[1].check(
          "a/b/c/d/a/b/c/d", {{0, "a"}, {1, "d"}, {1, "a"}, {1, "b"}, {1, "c"}, {1, "d"}}, "ABCDABCD"));
        TEST_ASSERT(
          col.get_matches()[2].check("a/b/c/d/b/c/d", {{0, "a"}, {1, "d"}, {1, "b"}, {1, "c"}, {1, "d"}}, "ABCDBCD"));
    }

    kv.purge();
    TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_match_3()
{
    Memory mem(50);
    WildKV kv(mem);
    kv[""]  = "01";
    kv["/"] = "02";
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "*/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("", {}, "01"));
        TEST_ASSERT(col.get_matches()[1].check("/", {{0, ""}}, "02"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "/*"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(1, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("/", {{0, ""}}, "02"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "?/*/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT(col.get_only().check("/", {{0, ""}}, "02"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "*/?/"_wkv, &col, Collector::trampoline));
        TEST_ASSERT(col.get_only().check("/", {{1, ""}}, "02"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "*"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("", {{0, ""}}, "01"));
        TEST_ASSERT(col.get_matches()[1].check("/", {{0, ""}, {0, ""}}, "02"));
    }
    kv[""].erase();
    kv["/"].erase();
    TEST_ASSERT(wkv_is_empty(&kv));
}

void test_match_4()
{
    Memory mem(50);
    WildKV kv(mem);
    kv["a/z"]     = "01";
    kv["a/b/z"]   = "02";
    kv["a/b/c/z"] = "03";
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/*/z"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/z", {}, "01"));
        TEST_ASSERT(col.get_matches()[1].check("a/b/z", {{0, "b"}}, "02"));
        TEST_ASSERT(col.get_matches()[2].check("a/b/c/z", {{0, "b"}, {0, "c"}}, "03"));
    }
    {
        Collector col;
        TEST_ASSERT_NULL(wkv_match(&kv, "a/?/*/z"_wkv, &col, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, col.get_matches().size());
        TEST_ASSERT(col.get_matches()[0].check("a/b/z", {{0, "b"}}, "02"));
        TEST_ASSERT(col.get_matches()[1].check("a/b/c/z", {{0, "b"}, {1, "c"}}, "03"));
    }
    kv["a/z"].erase();
    kv["a/b/z"].erase();
    kv["a/b/c/z"].erase();
    TEST_ASSERT(wkv_is_empty(&kv));
}

void test_match_early_stop()
{
    Memory mem(50);
    WildKV kv(mem);
    kv["a/b/1"] = "ab1";
    kv["a/b/2"] = "ab2";
    kv["a/c/1"] = "ac1";
    kv["a/c/2"] = "ac2";
    kv["a/d/1"] = "ad1";
    kv["a/d/2"] = "ad2";
    kv["b/a/1"] = "ba1";
    kv["b/a/2"] = "ba2";

    using Hit                 = Collector::Hit;
    static const auto val_str = [](const Hit& hit) { return std::string_view(static_cast<const char*>(hit.value)); };

    {
        Collector col([&](const Hit& hit) -> void* { return ("-" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_NULL(wkv_match(&kv, "**"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ab1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_NULL(wkv_match(&kv, "a/b/2"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ab1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_NULL(wkv_match(&kv, "a/d/?"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ab1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_NULL(wkv_match(&kv, "b/*"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ab1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("ab1", wkv_match(&kv, "a/?/1"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ad1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("ad1", wkv_match(&kv, "a/?/1"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ad1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("ad1", wkv_match(&kv, "*/1"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ba1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("ba1", wkv_match(&kv, "b/*/a/1"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ba1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("ba1", wkv_match(&kv, "b/*/1"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ba1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("ba1", wkv_match(&kv, "*/1"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("ba1" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("ba1", wkv_match(&kv, "?/?/*/1"_wkv, &col, Collector::trampoline));
    }

    kv.purge();
}

void test_route()
{
    Memory mem(50);
    WildKV kv(mem);

    // Insert some patterns.
    kv[""]       = "01";
    kv["/"]      = "02";
    kv["a/b/c"]  = "03";
    kv["a/?/c"]  = "04";
    kv["?/b/?"]  = "05";
    kv["a/b/c/"] = "06";
    print(&kv.root);
    std::cout << "Fragments: " << mem.get_fragments() << ", OOMs: " << mem.get_oom_count() << std::endl;

    // Test some keys.
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, ""_wkv, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("", {}, "01"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "/"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("/", {}, "02"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_matches().empty());
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b/c/"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("a/b/c/", {}, "06"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b/c"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("?/b/?", {{0, "a"}, {1, "c"}}, "05"));
        TEST_ASSERT(collector.get_matches()[1].check("a/?/c", {{0, "b"}}, "04"));
        TEST_ASSERT(collector.get_matches()[2].check("a/b/c", {}, "03"));
    }

    // Add more patterns.
    kv["*"]     = "07";
    kv["*/"]    = "08";
    kv["a/*"]   = "09";
    kv["*/c/?"] = "0A";
    kv["*/b/*"] = "0B"; // dual * invalid, treated verbatim

    // Test same keys, get different results.
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, ""_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("*/", {}, "08"));
        TEST_ASSERT(collector.get_matches()[1].check("*", {{0, ""}}, "07"));
        TEST_ASSERT(collector.get_matches()[2].check("", {}, "01"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "/"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("*/", {{0, ""}}, "08"));
        TEST_ASSERT(collector.get_matches()[1].check("*", {{0, ""}, {0, ""}}, "07"));
        TEST_ASSERT(collector.get_matches()[2].check("/", {}, "02"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("*", {{0, "a"}, {0, "b"}}, "07"));
        TEST_ASSERT(collector.get_matches()[1].check("a/*", {{0, "b"}}, "09"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b/c/"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(5, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("*/c/?", {{0, "a"}, {0, "b"}, {1, ""}}, "0A"));
        TEST_ASSERT(collector.get_matches()[1].check("*/", {{0, "a"}, {0, "b"}, {0, "c"}}, "08"));
        TEST_ASSERT(collector.get_matches()[2].check("*", {{0, "a"}, {0, "b"}, {0, "c"}, {0, ""}}, "07"));
        TEST_ASSERT(collector.get_matches()[3].check("a/*", {{0, "b"}, {0, "c"}, {0, ""}}, "09"));
        TEST_ASSERT(collector.get_matches()[4].check("a/b/c/", {}, "06"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b/c"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(5, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("?/b/?", {{0, "a"}, {1, "c"}}, "05"));
        TEST_ASSERT(collector.get_matches()[1].check("*", {{0, "a"}, {0, "b"}, {0, "c"}}, "07"));
        TEST_ASSERT(collector.get_matches()[2].check("a/?/c", {{0, "b"}}, "04"));
        TEST_ASSERT(collector.get_matches()[3].check("a/*", {{0, "b"}, {0, "c"}}, "09"));
        TEST_ASSERT(collector.get_matches()[4].check("a/b/c", {}, "03"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "c/z"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("*/c/?", {{1, "z"}}, "0A"));
        TEST_ASSERT(collector.get_matches()[1].check("*", {{0, "c"}, {0, "z"}}, "07"));
    }
    {
        Collector collector; // The second * in "*/b/*" is treated verbatim.
        TEST_ASSERT_NULL(wkv_route(&kv, "z/b/*"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(3, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("?/b/?", {{0, "z"}, {1, "*"}}, "05"));
        TEST_ASSERT(collector.get_matches()[1].check("*/b/*", {{0, "z"}}, "0B"));
        TEST_ASSERT(collector.get_matches()[2].check("*", {{0, "z"}, {0, "b"}, {0, "*"}}, "07"));
    }

    kv.purge();
    TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_route_2()
{
    Memory mem(50);
    WildKV kv(mem);
    kv["x"]   = "01";
    kv["*/x"] = "02";
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/x"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("*/x", {{0, "a"}}, "02"));
    }
    kv.purge();
    TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_route_3()
{
    Memory mem(50);
    WildKV kv(mem);
    kv["a/*/z"]   = "01";
    kv["a/?/*/z"] = "02";
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/z"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT(collector.get_only().check("a/*/z", {}, "01"));
    }
    {
        Collector collector;
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b/z"_wkv, &collector, Collector::trampoline));
        TEST_ASSERT_EQUAL_size_t(2, collector.get_matches().size());
        TEST_ASSERT(collector.get_matches()[0].check("a/?/*/z", {{0, "b"}}, "02"));
        TEST_ASSERT(collector.get_matches()[1].check("a/*/z", {{0, "b"}}, "01"));
    }
    kv.purge();
    TEST_ASSERT_EQUAL_size_t(0, count(&kv));
    TEST_ASSERT_EQUAL_size_t(0, mem.get_fragments());
}

void test_route_early_stop()
{
    Memory mem(50);
    WildKV kv(mem);
    kv["*"]       = "a";
    kv["a/b/*"]   = "b";
    kv["a/d/?"]   = "c";
    kv["a/*/b"]   = "d";
    kv["a/?/d"]   = "e";
    kv["*/?/?"]   = "f";
    kv["?/?/?"]   = "g";
    kv["*/*/?/?"] = "h";
    kv["?/?/*/?"] = "i";

    using Hit                 = Collector::Hit;
    static const auto val_str = [](const Hit& hit) { return std::string_view(static_cast<const char*>(hit.value)); };
    {
        Collector col([&](const Hit& hit) -> void* { return ("-" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b/c"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("a" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("a", wkv_route(&kv, "a/b/c"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("b" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("b", wkv_route(&kv, "a/b/c"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("c" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_NULL(wkv_route(&kv, "a/b/c"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("c" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("c", wkv_route(&kv, "a/d/c"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("d" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("d", wkv_route(&kv, "a/x/b"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("e" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("e", wkv_route(&kv, "a/x/d"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("f" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("f", wkv_route(&kv, "a/x/d"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("g" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("g", wkv_route(&kv, "a/x/d"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("h" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("h", wkv_route(&kv, "a/*/x/y"_wkv, &col, Collector::trampoline));
    }
    {
        Collector col([&](const Hit& hit) -> void* { return ("i" == val_str(hit)) ? hit.value : nullptr; });
        TEST_ASSERT_EQUAL_STRING("i", wkv_route(&kv, "x/y/z"_wkv, &col, Collector::trampoline));
    }
    kv.purge();
}

void test_has_substitution_tokens()
{
    Memory mem(50);
    WildKV kv(mem);

    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, ""_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "/"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "/a"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "a/"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "a/b/c"_wkv));

    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "??"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "*?/a"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "?x/a"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "a/?x"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "a/x?"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "a/x?/c"_wkv));
    TEST_ASSERT_FALSE(::wkv_has_substitution_tokens(&kv, "a/?x/c"_wkv));

    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "?"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "?/a"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "?/a"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "a/?"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "a/?"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "a/?/c"_wkv));

    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "*"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "*/a"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "*/a"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "a/*"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "a/*"_wkv));
    TEST_ASSERT(::wkv_has_substitution_tokens(&kv, "a/*/c"_wkv));
}

void test_misc()
{
    TEST_ASSERT_EQUAL_size_t(0, ::wkv_key(nullptr).len);
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
    RUN_TEST(test_reconstruct);

    RUN_TEST(test_match);
    RUN_TEST(test_match_2);
    RUN_TEST(test_match_3);
    RUN_TEST(test_match_4);
    RUN_TEST(test_match_early_stop);

    RUN_TEST(test_route);
    RUN_TEST(test_route_2);
    RUN_TEST(test_route_3);
    RUN_TEST(test_route_early_stop);

    RUN_TEST(test_has_substitution_tokens);
    RUN_TEST(test_misc);

    return UNITY_END();
    // NOLINTEND(misc-include-cleaner)
}
