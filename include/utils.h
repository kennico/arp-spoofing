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

//    class observer {
//    public:
//
//        observer(u_char* buf_, size_t size_) : buffer(buf_), size(size_) {
//
//        }
//
//    public:
//
//        inline const u_char * buf() const noexcept {
//            return buffer;
//        }
//
//        inline u_char * buf() noexcept {
//            return buffer;
//        }
//
//        inline size_t bufsize() const noexcept {
//            return size;
//        }
//
//    private:
//
//        u_char * buffer;
//        size_t size;
//
//    };
//
//    class auto_buf {
//    public:
//
//        explicit auto_buf(size_t size_): mem(new u_char[size]), size(size_) {
//
//        }
//
////        auto_buf(auto_buf&&) = default; // https://stackoverflow.com/a/18290839/8706476
//
//        auto_buf(auto_buf&& b) : mem(std::move(b.mem)), size(b.size) {
//            printf("move\n");
//        }
//
//        inline const u_char * buf() const noexcept {
//            return mem.get();
//        }
//
//        inline u_char * buf() noexcept {
//            return mem.get();
//        }
//
//
//        inline size_t bufsize() const noexcept {
//            return size;
//        }
//
//    private:
//        std::unique_ptr<u_char[]> mem;
//        size_t size{};
//    };

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