//
// Created by kenny on 2/7/19.
//


#include <gtest/gtest.h>
#include "../src/hdrs.h"

TEST(Usage, MultiMapEraseKeyValue) {
    std::multimap<char, int> map;

    map.insert(std::make_pair('a', 1));
    map.insert(std::make_pair('a', 2));
    map.insert(std::make_pair('a', 3));
    map.insert(std::make_pair('a', 4));
    map.insert(std::make_pair('b', 5));
    map.insert(std::make_pair('c', 6));
    map.insert(std::make_pair('d', 7));
    map.insert(std::make_pair('e', 8));

    auto range = map.equal_range('a');

}

