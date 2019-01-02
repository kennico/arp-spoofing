//
// Created by kenny on 1/3/19.
//
#include <iostream>
#include "common.h"


template <typename T>
void func(const T & t) {
    std::cout<<t<<std::endl;
}

int main(int argc, char* argv[]) {
    char a[5] = "1234";
    func(a);
}