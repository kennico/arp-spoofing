//
// Created by kenny on 2/7/19.
//
#ifdef KNI_DEBUG

#include <gtest/gtest.h>

#include "../src/hdrs.h"
#include "../src/fake-port.h"
#include "utils.h"


TEST(ReverseMap, Map) {
    kni::reverse_values<char, int> m;
    m.map('a', 1);
    m.map('b', 1);
    m.map('c', 2);
    m.map('d', 3);
    m.map('e', 2);

    std::set<char> keys = {'a', 'b'};
    EXPECT_EQ(keys, m.rmap(1));

    keys = {'c', 'e'};
    EXPECT_EQ(keys, m.rmap(2));
}

TEST(ReverseMap, MapDuplicateKeys) {
    kni::reverse_values<char, int> m;
    m.map('a', 1);
    m.map('b', 1);
    m.map('c', 2);
    m.map('d', 3);
    m.map('e', 2);

    m.map('a', 2);
    m.map('b', 5);

    EXPECT_FALSE(m.has_value(1));

    std::set<char> keys = {'a', 'c', 'e'};
    EXPECT_EQ(keys, m.rmap(2));

    keys = {'b'};
    EXPECT_EQ(keys, m.rmap(5));
}

TEST(ReverseMap, Map2) {
    kni::reverse_values<std::string, int> m;
    // Insertion
    m.map("aaa", 1);
    m.map("bbb", 1);
    m.map("ccc", 2);
    m.map("ddd", 3);
    m.map("eee", 2);
    m.map("fff", 1);

    // Count values
    std::set<std::string> keys = {"aaa", "bbb", "fff"};
    EXPECT_EQ(keys, m.rmap(1));
    EXPECT_EQ(3, m.count(1));
    EXPECT_TRUE(m.has_key("bbb"));

    // Delete a key
    m.erase_key("bbb");
    EXPECT_FALSE(m.has_key("bbb"));
    EXPECT_EQ(2, m.count(1));

    keys = {"aaa", "fff"};
    EXPECT_EQ(keys, m.rmap(1));

    // Update values
    m.update(1, 4);
    EXPECT_FALSE(m.has_value(1));
    EXPECT_EQ(keys, m.rmap(4));

    m.update(4, 3);
    keys = {"aaa", "fff", "ddd"};
    EXPECT_EQ(keys, m.rmap(3));

    // Delete keys with the given value
    m.erase_value(3);
    EXPECT_FALSE(m.has_value(3));
    EXPECT_FALSE(m.has_key("aaa"));
    EXPECT_FALSE(m.has_key("fff"));
    EXPECT_FALSE(m.has_key("ddd"));
}

#endif // KNI_DEBUG
