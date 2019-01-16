//
// Created by kenny on 1/16/19.
//

#include <gtest/gtest.h>
#include <memory>

TEST(Usage, MoveUniquePtr) {

    struct unamed {

        unamed(int n) : id(n) {
            printf("Unamed %d construted\n", id);
        }

        unamed(const unamed &u) : id(u.id) {
            printf("Unamed %d copied\n", id);
        }

        ~unamed() {
            printf("Unamed %d to be deallocated\n", id);
        }

        int id{0};

    };

    std::unique_ptr<unamed> a(new unamed(99));
    printf("unique_ptr a:%d\n", a->id);

    std::unique_ptr<unamed> b = std::move(a);
    EXPECT_NO_THROW(printf("unique_ptr b:%d\n", b->id));
//    std::unique_ptr<unamed> c = a;
}

