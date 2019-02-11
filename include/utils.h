//
// Created by kenny on 1/14/19.
//

#pragma once

#include <sys/types.h>
#include <netinet/in.h>

#include <memory>
#include <map>
#include <set>

#include <cstring>
#include <cassert>

#include <pcap.h>

namespace kni {

    inline int count_bits(unsigned int n) {
        int count = 0;
        while (n) {
            if (n & 0x1) // NOLINT
                count++;
            n >>= 1;
        }
        return count;
    }

    inline uint16_t sum_all_words(const void *buf, size_t bytes, uint16_t sum = 0) {
        assert(bytes % 2 == 0);

        uint32_t tmp = sum;

        auto w = (uint16_t *) buf;
        auto wc = bytes / 2;

        for (int i = 0; i < wc; ++i) {
            tmp += ntohs(w[i]); // tmp < 0x0001FFFF due to 2 * 0x0000FFFF(maximum of uint16_t) = 0x0001FFFE
            tmp = (0x0000FFFF & tmp) + (tmp >> 16); // NOLINT
        }

        return static_cast<uint16_t>(tmp);
    }

    /**
     * Add up all 16-bit words using one's complement arithmetic and flip the result
     *
     * @param buf
     * @param bytes
     * @return
     */
    inline uint16_t compute_check(const void *buf, size_t bytes) {
        return (~sum_all_words(buf, bytes));
    }

    class managed_error {
    public:
        explicit managed_error(size_t size) : mem(new char[size]), mem_len(size) {

        }

        inline const char *err() const noexcept {
            return mem.get();
        }

        inline char *err() noexcept {
            return mem.get();
        }

        inline size_t errbufsize() const noexcept {
            return mem_len;
        }
        /**
         * Retrieve and store library or system error information via errno
         * @return a buffer containing error information
         */
        inline const char *getsyserr() noexcept {
            strerror_r(errno, err(), errbufsize());
            return err();
        }

    private:
        std::unique_ptr<char[]> mem;
        size_t mem_len;
    };

    class pcap_error : public managed_error {
    public:
        explicit pcap_error(size_t size = PCAP_ERRBUF_SIZE) : managed_error(size) {

        }

    };


    /**
     * TODO Impl iterator?
     *
     * Non-injective mapping distinguished with the std::multimap
     *
     * @tparam K
     * @tparam V
     */
    template<typename K, typename V>
    class reverse_values {
    public:
        /**
         * Insert a key-value pair
         *
         * @param key
         * @param value
         */
        inline void map(const K &key, const V &value) {
            if (has_key(key))
                erase_key(key);

            if (reverse.count(value) == 0) {
                std::set<K> tmp;
                tmp.insert(key);
                reverse[value] = std::move(tmp);
            } else {
                reverse[value].insert(key);
            }

            auto insert_succ = direct.insert(std::make_pair(key, value)).second;
            assert(insert_succ);
        }

        inline bool empty() const noexcept {
            assert(direct.empty() == reverse.empty());
            return direct.empty();
        }

        inline bool has_key(const K &key) const noexcept {
            return direct.count(key) == 1;
        }

        /**
         *
         * @param value
         * @return the count of keys with the same given value
         */
        inline size_t count(const V &value) const noexcept {
            if (has_value(value)) {
                return rmap(value).size();
            } else {
                return 0;
            }
        }

        inline bool has_value(const V &value) const noexcept {
            return reverse.count(value) == 1;
        }

        inline const std::map<K, V> &m() const noexcept {
            return direct;
        };

        inline const V &map(const K &key) const noexcept {
            return direct.at(key);
        }

        /**
         * Throw std::out_of_range if such value does not exist
         *
         * @param value
         * @return a set of keys having the same value
         */
        inline const std::set<K> &rmap(const V &value) const noexcept {
            return reverse.at(value);
        }

        inline const std::map<V, std::set<K>> &r() const noexcept {
            return reverse;
        };

        /**
         *
         * @param key not guaranteed to be present in this mapping
         */
        inline void erase_key(const K &key) noexcept {
            auto value = direct[key];

            reverse[value].erase(key);
            if (reverse[value].empty())
                reverse.erase(value);

            direct.erase(key);
        }

        inline void erase_value(const V &value) noexcept {
            for (auto key : reverse.at(value))
                direct.erase(key);
            reverse.erase(value);
        }

        /**
         *
         * @param old not guaranteed to be present in this mapping
         * @param now
         * @return
         */
        inline void update(const V &old, const V &now) {
            for (auto key: reverse.at(old))
                direct[key] = now;

            if (reverse.count(now) == 1)
                reverse[now].insert(reverse[old].begin(),
                                    reverse[old].end()); // If the new value already exists, then merge two sets
            else
                reverse[now] = std::move(reverse[old]); // Insert as a brand new element

            reverse.erase(old);
        }

    private:
        std::map<K, V> direct;
        std::map<V, std::set<K>> reverse;
    };


}