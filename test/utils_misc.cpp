//
// Created by kenny on 2/7/19.
//
#ifdef KNI_DEBUG

#include <gtest/gtest.h>

#include "../src/hdrs.h"
#include "../src/fake-port.h"
#include "utils.h"


TEST(ReverseMap, AddMapping) {
    kni::reverse_map<char, int> m;
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

TEST(ReverseMap, AddMapping2) {
    kni::reverse_map<std::string, int> m;
    // Insertion
    EXPECT_TRUE(m.map("aaa", 1));
    EXPECT_TRUE(m.map("bbb", 1));
    EXPECT_TRUE(m.map("ccc", 2));
    EXPECT_TRUE(m.map("ddd", 3));
    EXPECT_TRUE(m.map("eee", 2));
    EXPECT_TRUE(m.map("fff", 1));

    // Duplicate keys
    EXPECT_FALSE(m.map("aaa", 2));
    EXPECT_FALSE(m.map("aaa", 1));

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

TEST(FakePortManager, UsingInitialPorts) {

    std::vector<kni::port_t> exp = {1, 2, 3, 4, 5};
    std::vector<kni::port_t> res;

    kni::fake_port_manager mgr(1, 6, 2);

    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());

    EXPECT_EQ(exp, res);
}

TEST(FakePortManager, UsingRecycle) {

    std::vector<kni::port_t> exp = {1, 2, 3, 2, 4, 3, 5};
    std::vector<kni::port_t> res;

    kni::fake_port_manager mgr(1, 6, 2);

    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());
    mgr.free(2);
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());
    mgr.free(3);
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());

    EXPECT_EQ(exp, res);
}

TEST(FakePortManager, UsingOutdatedPort) {
    std::vector<kni::port_t> exp = {1, 2, 3, 4, 1, 2, 3, 4, 1, 2};
    std::vector<kni::port_t> res;

    kni::fake_port_manager mgr(1, 5, 2);

    res.push_back(mgr.alloc()); // 1
    res.push_back(mgr.alloc()); // 2
    res.push_back(mgr.alloc()); // 3
    sleep(2);
    res.push_back(mgr.alloc()); // 4
    res.push_back(mgr.alloc()); // 1
    res.push_back(mgr.alloc()); // 2
    mgr.free(4);
    res.push_back(mgr.alloc()); // 3
    res.push_back(mgr.alloc()); // 4
    sleep(2);
    res.push_back(mgr.alloc()); // 1
    res.push_back(mgr.alloc()); // 2

    EXPECT_EQ(exp, res);
}

TEST(FakePortManager, UsingOutdatedPort2) {
    std::vector<kni::port_t> exp = {10036, 10037, 10038, 10039, 10036, 10037};
    std::vector<kni::port_t> res;

    kni::fake_port_manager mgr(10036, 10040, 2);

    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());

    sleep(2);
    res.push_back(mgr.alloc());
    res.push_back(mgr.alloc());

    EXPECT_EQ(exp, res);
}

#endif // KNI_DEBUG
