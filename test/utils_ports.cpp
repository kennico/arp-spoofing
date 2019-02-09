//
// Created by kenny on 2/9/19.
//

#include <gtest/gtest.h>
#include "../src/fake-port.h"

using namespace kni;

TEST(FakePortManager, AllocFromStart) {

    kni::fake_port_manager mgr(1, 6, 2);

    for (int i = 1; i < 6; ++i)
        EXPECT_EQ(i, mgr.alloc());

}

TEST(FakePortManager, AllocFromFreeQueue) {

    kni::fake_port_manager mgr(1, 6, 2);

    EXPECT_EQ(1, mgr.alloc());
    EXPECT_EQ(2, mgr.alloc());
    EXPECT_EQ(3, mgr.alloc());
    mgr.free(2);
    EXPECT_EQ(2, mgr.alloc());
    EXPECT_EQ(4, mgr.alloc());
    mgr.free(3);
    EXPECT_EQ(3, mgr.alloc());
    EXPECT_EQ(5, mgr.alloc());

}

TEST(FakePortManager, AllocFromTimeout) {

    kni::fake_port_manager mgr(1, 5, 2);

    EXPECT_EQ(1, mgr.alloc()); // 1
    EXPECT_EQ(2, mgr.alloc()); // 2
    EXPECT_EQ(3, mgr.alloc()); // 3
    sleep(2);
    EXPECT_EQ(4, mgr.alloc()); // 4
    EXPECT_EQ(1, mgr.alloc()); // 1
    EXPECT_EQ(2, mgr.alloc()); // 2
    mgr.free(4);
    EXPECT_EQ(3, mgr.alloc()); // 3
    EXPECT_EQ(4, mgr.alloc()); // 4
    sleep(2);
    EXPECT_EQ(1, mgr.alloc()); // 1
    EXPECT_EQ(2, mgr.alloc()); // 2
}

TEST(FakePortManager, AllocFromTimeout2) {

    kni::fake_port_manager mgr(10036, 10040, 2);

    EXPECT_EQ(10036, mgr.alloc());
    EXPECT_EQ(10037, mgr.alloc());
    EXPECT_EQ(10038, mgr.alloc());
    EXPECT_EQ(10039, mgr.alloc());

    sleep(2);
    EXPECT_EQ(10036, mgr.alloc());
    EXPECT_EQ(10037, mgr.alloc());
}

TEST(FakePortManager, AllocRefresh) {
    kni::fake_port_manager mgr(10036, 10040, 4);

    EXPECT_EQ(10036, mgr.alloc());
    sleep(1);

    EXPECT_EQ(10037, mgr.alloc());
    EXPECT_EQ(10038, mgr.alloc());
    EXPECT_EQ(10039, mgr.alloc());
    sleep(3);                           // 10036 timeout

    EXPECT_FALSE(mgr.refresh(10036));   // 10036 timeout
    EXPECT_EQ(10036, mgr.alloc());
    EXPECT_TRUE(mgr.refresh(10037));    // 10037 still in used
    sleep(1);                           // 10038 and 10039 timeout

    EXPECT_EQ(10038, mgr.alloc());
    EXPECT_EQ(10039, mgr.alloc());

}