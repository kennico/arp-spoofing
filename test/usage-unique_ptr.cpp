//
// Created by kenny on 1/16/19.
//

#include <gtest/gtest.h>
#include <memory>

TEST(Usage, MoveUniquePtr) {
    static std::string o;

    struct unamed {

        unamed() {
            o += "ctor";
        }

        unamed(const unamed &u) {
            o += "copy";
        }

        ~unamed() {
            o += "dtor";
        }

    };

    std::unique_ptr<unamed> a(new unamed());
    std::unique_ptr<unamed> b = std::move(a);

    EXPECT_EQ("ctor", o);
    EXPECT_NO_THROW(printf("unique_ptr b:%p\n", b.get()));
//    std::unique_ptr<unamed> c = a;
}

TEST(Usage, SussesiveCall) {
    struct t {
        t &operator()(char c) {
            s.push_back(c);
            return *this;
        }

        std::string s;
    };

    t u;
    u('A')('B')('C')('D');

    EXPECT_EQ("ABCD", u.s);
}
