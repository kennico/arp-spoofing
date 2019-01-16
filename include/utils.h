//
// Created by kenny on 1/14/19.
//

#pragma once

#include <sys/types.h>

#include <memory>
#include <cstring>

namespace kni {

    inline int count_bits(unsigned int n) {
        int count = 0;
        while (n) {
            if (n & 0x1)
                count++;
            n >>= 1;
        }
        return count;
    }


    class buffered_error {
    public:
        buffered_error(char *eb, size_t size) : buf(eb), bufsize(size) {

        }

        inline const char *error() const noexcept {
            return buf;
        }

        inline size_t errbufsize() const noexcept {
            return bufsize;
        }

        inline const char *getsyserr() noexcept {
            strerror_r(errno, errbuf(), errbufsize());
            return errbuf();
        }

    protected:

        inline char *errbuf() noexcept {
            return buf;
        }

    private:
        char *buf{nullptr};
        size_t bufsize{0};
    };

}