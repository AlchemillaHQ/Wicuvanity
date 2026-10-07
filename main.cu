/**
 * MIT License
 *
 * Copyright (c) 2024-2025 shtrophic <christoph at liebender dot dev>
 * Copyright (c) 2018-2026 Brian Warner, Shengqi Chen
 * Copyright (c) 2026 Alchemilla Ventures Private Limited <hello@alchemilla.io>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <algorithm>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cstdio>
#ifndef WICUVANITY_HOST_TEST
    #include <cxxopts.hpp>
#endif
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdlib.h>
#include <vector>

using u128 = unsigned __int128;
typedef uint64_t field_elem[5];
typedef unsigned char u8;

constexpr uint64_t field_mask51 = (1ULL << 51) - 1;
constexpr uint64_t field_sub_bias0 = 2 * field_mask51 - 36;
constexpr uint64_t field_sub_bias = 2 * field_mask51;

struct ChaChaSeed {
    uint32_t key[8];
    uint32_t nonce[3];
};

struct Match {
    u8 private_key[32];
    u8 public_key[32];
};

volatile std::sig_atomic_t stop_requested = 0;

void request_stop(int) {
    stop_requested = 1;
}

__host__ __device__ uint32_t rotate_left(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

__host__ __device__ void chacha_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b;
    d ^= a;
    d = rotate_left(d, 16);
    c += d;
    b ^= c;
    b = rotate_left(b, 12);
    a += b;
    d ^= a;
    d = rotate_left(d, 8);
    c += d;
    b ^= c;
    b = rotate_left(b, 7);
}

__host__ __device__ void chacha20_block(uint32_t out[8], const ChaChaSeed& seed, uint64_t counter) {
    uint32_t initial[16] = {
        0x61707865,
        0x3320646e,
        0x79622d32,
        0x6b206574,
        seed.key[0],
        seed.key[1],
        seed.key[2],
        seed.key[3],
        seed.key[4],
        seed.key[5],
        seed.key[6],
        seed.key[7],
        static_cast<uint32_t>(counter),
        seed.nonce[0] ^ static_cast<uint32_t>(counter >> 32),
        seed.nonce[1],
        seed.nonce[2],
    };
    uint32_t state[16];

#ifdef __CUDA_ARCH__
    #pragma unroll
#endif
    for (int i = 0; i < 16; i++) {
        state[i] = initial[i];
    }

#ifdef __CUDA_ARCH__
    #pragma unroll
#endif
    for (int i = 0; i < 10; i++) {
        chacha_quarter_round(state[0], state[4], state[8], state[12]);
        chacha_quarter_round(state[1], state[5], state[9], state[13]);
        chacha_quarter_round(state[2], state[6], state[10], state[14]);
        chacha_quarter_round(state[3], state[7], state[11], state[15]);
        chacha_quarter_round(state[0], state[5], state[10], state[15]);
        chacha_quarter_round(state[1], state[6], state[11], state[12]);
        chacha_quarter_round(state[2], state[7], state[8], state[13]);
        chacha_quarter_round(state[3], state[4], state[9], state[14]);
    }

#ifdef __CUDA_ARCH__
    #pragma unroll
#endif
    for (int i = 0; i < 8; i++) {
        out[i] = state[i] + initial[i];
    }
}

__host__ __device__ void genpriv(u8 privkey[32], const ChaChaSeed& seed, uint64_t counter) {
    uint32_t random[8];
    chacha20_block(random, seed, counter);
#ifdef __CUDA_ARCH__
    #pragma unroll
#endif
    for (int i = 0; i < 8; i++) {
        privkey[4 * i] = random[i];
        privkey[4 * i + 1] = random[i] >> 8;
        privkey[4 * i + 2] = random[i] >> 16;
        privkey[4 * i + 3] = random[i] >> 24;
    }
    privkey[0] &= 0xf8;
    privkey[31] = (privkey[31] & 0x3f) | 0x40;
}

bool chacha20_self_test() {
    ChaChaSeed seed = {
        {
            0x03020100,
            0x07060504,
            0x0b0a0908,
            0x0f0e0d0c,
            0x13121110,
            0x17161514,
            0x1b1a1918,
            0x1f1e1d1c,
        },
        { 0x09000000, 0x4a000000, 0x00000000 },
    };
    const uint32_t expected[8] = {
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
    };
    uint32_t actual[8];
    chacha20_block(actual, seed, 1);
    for (int i = 0; i < 8; i++) {
        if (actual[i] != expected[i]) {
            return false;
        }
    }
    return true;
}

__device__ __forceinline__ void field_elem_copy(field_elem out, const field_elem in) {
    for (int i = 0; i < 5; i++) {
        out[i] = in[i];
    }
}

__device__ __forceinline__ void
field_elem_add(field_elem out, const field_elem a, const field_elem b) {
    for (int i = 0; i < 5; i++) {
        out[i] = a[i] + b[i];
    }
}

__device__ __forceinline__ void
field_elem_sub(field_elem out, const field_elem a, const field_elem b) {
    out[0] = a[0] + field_sub_bias0 - b[0];
    for (int i = 1; i < 5; i++) {
        out[i] = a[i] + field_sub_bias - b[i];
    }
}

__device__ __forceinline__ void
field_elem_reduce(u128 h0, u128 h1, u128 h2, u128 h3, u128 h4, field_elem out) {
    h3 += h2 >> 51;
    uint64_t g2 = static_cast<uint64_t>(h2) & field_mask51;
    h1 += h0 >> 51;
    uint64_t g0 = static_cast<uint64_t>(h0) & field_mask51;
    h4 += h3 >> 51;
    uint64_t g3 = static_cast<uint64_t>(h3) & field_mask51;
    g2 += static_cast<uint64_t>(h1 >> 51);
    uint64_t g1 = static_cast<uint64_t>(h1) & field_mask51;
    g0 += static_cast<uint64_t>(h4 >> 51) * 19;
    uint64_t g4 = static_cast<uint64_t>(h4) & field_mask51;
    g3 += g2 >> 51;
    g2 &= field_mask51;
    g1 += g0 >> 51;
    g0 &= field_mask51;
    out[0] = g0;
    out[1] = g1;
    out[2] = g2;
    out[3] = g3;
    out[4] = g4;
}

__device__ __forceinline__ void
field_elem_mul(field_elem out, const field_elem a, const field_elem b) {
    uint64_t f0 = a[0], f1 = a[1], f2 = a[2], f3 = a[3], f4 = a[4];
    uint64_t g0 = b[0], g1 = b[1], g2 = b[2], g3 = b[3], g4 = b[4];
    u128 h0 = static_cast<u128>(f0) * g0;
    u128 h1 = static_cast<u128>(f0) * g1;
    u128 h2 = static_cast<u128>(f0) * g2;
    u128 h3 = static_cast<u128>(f0) * g3;
    u128 h4 = static_cast<u128>(f0) * g4;
    f0 = f1;
    h0 += static_cast<u128>(f0) * (g4 *= 19);
    h1 += static_cast<u128>(f0) * g0;
    h2 += static_cast<u128>(f0) * g1;
    h3 += static_cast<u128>(f0) * g2;
    h4 += static_cast<u128>(f0) * g3;
    f0 = f2;
    h0 += static_cast<u128>(f0) * (g3 *= 19);
    h1 += static_cast<u128>(f0) * g4;
    h2 += static_cast<u128>(f0) * g0;
    h3 += static_cast<u128>(f0) * g1;
    h4 += static_cast<u128>(f0) * g2;
    f0 = f3;
    h0 += static_cast<u128>(f0) * (g2 *= 19);
    h1 += static_cast<u128>(f0) * g3;
    h2 += static_cast<u128>(f0) * g4;
    h3 += static_cast<u128>(f0) * g0;
    h4 += static_cast<u128>(f0) * g1;
    f0 = f4;
    h0 += static_cast<u128>(f0) * (g1 *= 19);
    h1 += static_cast<u128>(f0) * g2;
    h2 += static_cast<u128>(f0) * g3;
    h3 += static_cast<u128>(f0) * g4;
    h4 += static_cast<u128>(f0) * g0;
    field_elem_reduce(h0, h1, h2, h3, h4, out);
}

__device__ __forceinline__ void field_elem_sq(field_elem out, const field_elem a) {
    uint64_t g0 = a[0], g1 = a[1], g2 = a[2], g3 = a[3], g4 = a[4];
    u128 h0 = static_cast<u128>(g0) * g0;
    g0 *= 2;
    u128 h1 = static_cast<u128>(g0) * g1;
    u128 h2 = static_cast<u128>(g0) * g2;
    u128 h3 = static_cast<u128>(g0) * g3;
    u128 h4 = static_cast<u128>(g0) * g4;
    g0 = g4;
    h3 += static_cast<u128>(g0) * (g4 *= 19);
    h2 += static_cast<u128>(g1) * g1;
    g1 *= 2;
    h3 += static_cast<u128>(g1) * g2;
    h4 += static_cast<u128>(g1) * g3;
    h0 += static_cast<u128>(g1) * g4;
    g0 = g3;
    h1 += static_cast<u128>(g0) * (g3 *= 19);
    h2 += static_cast<u128>(g0 * 2) * g4;
    h4 += static_cast<u128>(g2) * g2;
    g2 *= 2;
    h0 += static_cast<u128>(g2) * g3;
    h1 += static_cast<u128>(g2) * g4;
    field_elem_reduce(h0, h1, h2, h3, h4, out);
}

__device__ __forceinline__ void field_elem_add_mul_small(
    field_elem out,
    const field_elem a,
    const field_elem b,
    uint64_t constant
) {
    u128 h0 = static_cast<u128>(a[0]) + static_cast<u128>(constant) * b[0];
    u128 h1 = static_cast<u128>(a[1]) + static_cast<u128>(constant) * b[1];
    u128 h2 = static_cast<u128>(a[2]) + static_cast<u128>(constant) * b[2];
    u128 h3 = static_cast<u128>(a[3]) + static_cast<u128>(constant) * b[3];
    u128 h4 = static_cast<u128>(a[4]) + static_cast<u128>(constant) * b[4];
    field_elem_reduce(h0, h1, h2, h3, h4, out);
}

__device__ __forceinline__ void
field_elem_mul_small(field_elem out, const field_elem a, uint64_t constant) {
    const field_elem zero = { 0, 0, 0, 0, 0 };
    field_elem_add_mul_small(out, zero, a, constant);
}

__device__ __forceinline__ void swap25519(field_elem p, field_elem q, int bit) {
    const uint64_t mask = -static_cast<uint64_t>(bit);
    for (int i = 0; i < 5; i++) {
        const uint64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

__device__ void field_elem_inv(field_elem out, const field_elem in) {
    field_elem t0, t1, t2, t3;
    field_elem_sq(t0, in);
    field_elem_sq(t1, t0);
    field_elem_sq(t1, t1);
    field_elem_mul(t1, in, t1);
    field_elem_mul(t0, t0, t1);
    field_elem_sq(t2, t0);
    field_elem_mul(t1, t1, t2);
    field_elem_sq(t2, t1);
    for (int i = 1; i < 5; i++) {
        field_elem_sq(t2, t2);
    }
    field_elem_mul(t1, t2, t1);
    field_elem_sq(t2, t1);
    for (int i = 1; i < 10; i++) {
        field_elem_sq(t2, t2);
    }
    field_elem_mul(t2, t2, t1);
    field_elem_sq(t3, t2);
    for (int i = 1; i < 20; i++) {
        field_elem_sq(t3, t3);
    }
    field_elem_mul(t2, t3, t2);
    for (int i = 0; i < 10; i++) {
        field_elem_sq(t2, t2);
    }
    field_elem_mul(t1, t2, t1);
    field_elem_sq(t2, t1);
    for (int i = 1; i < 50; i++) {
        field_elem_sq(t2, t2);
    }
    field_elem_mul(t2, t2, t1);
    field_elem_sq(t3, t2);
    for (int i = 1; i < 100; i++) {
        field_elem_sq(t3, t3);
    }
    field_elem_mul(t2, t3, t2);
    for (int i = 0; i < 50; i++) {
        field_elem_sq(t2, t2);
    }
    field_elem_mul(t1, t2, t1);
    for (int i = 0; i < 5; i++) {
        field_elem_sq(t1, t1);
    }
    field_elem_mul(out, t1, t0);
}

__device__ void pack25519(u8 out[32], const field_elem in) {
    field_elem t;
    field_elem_copy(t, in);
    uint64_t q = (t[0] + 19) >> 51;
    q = (t[1] + q) >> 51;
    q = (t[2] + q) >> 51;
    q = (t[3] + q) >> 51;
    q = (t[4] + q) >> 51;
    t[0] += 19 * q;
    t[1] += t[0] >> 51;
    t[0] &= field_mask51;
    t[2] += t[1] >> 51;
    t[1] &= field_mask51;
    t[3] += t[2] >> 51;
    t[2] &= field_mask51;
    t[4] += t[3] >> 51;
    t[3] &= field_mask51;
    t[4] &= field_mask51;
    out[0] = t[0];
    out[1] = t[0] >> 8;
    out[2] = t[0] >> 16;
    out[3] = t[0] >> 24;
    out[4] = t[0] >> 32;
    out[5] = t[0] >> 40;
    out[6] = (t[0] >> 48) | (t[1] << 3);
    out[7] = t[1] >> 5;
    out[8] = t[1] >> 13;
    out[9] = t[1] >> 21;
    out[10] = t[1] >> 29;
    out[11] = t[1] >> 37;
    out[12] = (t[1] >> 45) | (t[2] << 6);
    out[13] = t[2] >> 2;
    out[14] = t[2] >> 10;
    out[15] = t[2] >> 18;
    out[16] = t[2] >> 26;
    out[17] = t[2] >> 34;
    out[18] = t[2] >> 42;
    out[19] = (t[2] >> 50) | (t[3] << 1);
    out[20] = t[3] >> 7;
    out[21] = t[3] >> 15;
    out[22] = t[3] >> 23;
    out[23] = t[3] >> 31;
    out[24] = t[3] >> 39;
    out[25] = (t[3] >> 47) | (t[4] << 4);
    out[26] = t[4] >> 4;
    out[27] = t[4] >> 12;
    out[28] = t[4] >> 20;
    out[29] = t[4] >> 28;
    out[30] = t[4] >> 36;
    out[31] = t[4] >> 44;
}

__device__ void genpub(const u8 privkey[32], u8 pub[32]) {
    field_elem x2 = { 6400, 0, 0, 0, 0 };
    field_elem z2 = { 157681440, 0, 0, 0, 0 };
    field_elem x3 = { 324, 0, 0, 0, 0 };
    field_elem z3 = { 36, 0, 0, 0, 0 };
    field_elem tmp0, tmp1;
    int swap = 1;

    for (int position = 253; position >= 0; position--) {
        const int bit = (privkey[position >> 3] >> (position & 7)) & 1;
        swap ^= bit;
        swap25519(x2, x3, swap);
        swap25519(z2, z3, swap);
        swap = bit;

        field_elem_sub(tmp0, x3, z3);
        field_elem_sub(tmp1, x2, z2);
        field_elem_add(x2, x2, z2);
        field_elem_add(z2, x3, z3);
        field_elem_mul(z3, tmp0, x2);
        field_elem_mul(z2, z2, tmp1);
        field_elem_sq(tmp0, tmp1);
        field_elem_sq(tmp1, x2);
        field_elem_add(x3, z3, z2);
        field_elem_sub(z2, z3, z2);
        field_elem_mul(x2, tmp1, tmp0);
        field_elem_sub(tmp1, tmp1, tmp0);
        field_elem_sq(z2, z2);
        field_elem_add_mul_small(tmp0, tmp0, tmp1, 121666);
        field_elem_sq(x3, x3);
        field_elem_mul_small(z3, z2, 9);
        field_elem_mul(z2, tmp1, tmp0);
    }

    swap25519(x2, x3, swap);
    swap25519(z2, z3, swap);
    field_elem_inv(tmp0, z2);
    field_elem_mul(tmp1, x2, tmp0);
    pack25519(pub, tmp1);
}

__host__ __device__ char cutolower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

__host__ __device__ char base64_char_at(const u8 in[32], int position) {
    static const char* b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if (position == 43) {
        return '=';
    }
    if (position == 42) {
        return b64chars[(in[31] & 15) << 2];
    }

    int byte = (position >> 2) * 3;
    switch (position & 3) {
        case 0:
            return b64chars[in[byte] >> 2];
        case 1:
            return b64chars[((in[byte] & 3) << 4) | (in[byte + 1] >> 4)];
        case 2:
            return b64chars[((in[byte + 1] & 15) << 2) | (in[byte + 2] >> 6)];
        default:
            return b64chars[in[byte + 2] & 63];
    }
}

void toBase64(const u8 in[32], char out[45]) {
    for (int i = 0; i < 44; i++) {
        out[i] = base64_char_at(in, i);
    }
    out[44] = '\0';
}

__device__ bool
matches(const u8 pubkey[32], const char* needle, int needlesize, int in, bool case_sensitive) {
    for (int start = 0; start <= in - needlesize; start++) {
        bool match = true;
        for (int i = 0; i < needlesize; i++) {
            char candidate = base64_char_at(pubkey, start + i);
            if (!case_sensitive) {
                candidate = cutolower(candidate);
            }
            if (candidate != needle[i]) {
                match = false;
                break;
            }
        }
        if (match) {
            return true;
        }
    }
    return false;
}

bool isBase64Needle(const std::string& needle) {
    constexpr auto alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    return needle.find_first_not_of(alphabet) == std::string::npos;
}

long double base64SymbolProbability(char needle, int position, bool case_sensitive) {
    if (position == 43) {
        return needle == '=' ? 1.0L : 0.0L;
    }

    static const char* b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (!case_sensitive) {
        needle = cutolower(needle);
    }
    int symbols = 0, matching_symbols = 0;
    for (int i = 0; i < 64; i++) {
        if ((position == 41 && (i & 8)) || (position == 42 && (i & 3))) {
            continue;
        }
        char candidate = case_sensitive ? b64chars[i] : cutolower(b64chars[i]);
        symbols++;
        matching_symbols += candidate == needle;
    }
    return static_cast<long double>(matching_symbols) / symbols;
}

long double estimatedCandidatesPerMatch(const std::string& needle, int in, bool case_sensitive) {
    long double log_probability_of_no_match = 0.0L;
    for (int start = 0; start <= in - static_cast<int>(needle.size()); start++) {
        long double probability_at_one_position = 1.0L;
        for (size_t i = 0; i < needle.size(); i++) {
            probability_at_one_position *=
                base64SymbolProbability(needle[i], start + static_cast<int>(i), case_sensitive);
        }
        if (probability_at_one_position == 1.0L) {
            return 1.0L;
        }
        log_probability_of_no_match += std::log1p(-probability_at_one_position);
    }

    long double probability_per_key = -std::expm1(log_probability_of_no_match);
    if (probability_per_key == 0.0L) {
        return std::numeric_limits<long double>::infinity();
    }
    return 1.0L / probability_per_key;
}

std::string formatDuration(long double seconds) {
    if (!std::isfinite(seconds)) {
        return "n/a";
    }

    std::ostringstream out;
    if (seconds < 1.0L) {
        return "<1s";
    }
    if (seconds < 10.0L) {
        out << std::fixed << std::setprecision(1) << seconds << 's';
        return out.str();
    }
    if (seconds < 60.0L) {
        out << static_cast<uint64_t>(seconds + 0.5L) << 's';
        return out.str();
    }

    constexpr uint64_t minute = 60;
    constexpr uint64_t hour = 60 * minute;
    constexpr uint64_t day = 24 * hour;
    constexpr long double year = 365.25L * day;
    if (seconds >= year) {
        long double years = seconds / year;
        if (years < 1000.0L) {
            out << std::fixed << std::setprecision(1) << years << 'y';
        } else {
            out << std::scientific << std::setprecision(2) << years << 'y';
        }
        return out.str();
    }

    uint64_t total = static_cast<uint64_t>(seconds + 0.5L);
    if (total < hour) {
        out << total / minute << 'm';
        if (total % minute != 0) {
            out << ' ' << total % minute << 's';
        }
    } else if (total < day) {
        out << total / hour << 'h';
        if ((total % hour) / minute != 0) {
            out << ' ' << (total % hour) / minute << 'm';
        }
    } else {
        out << total / day << 'd';
        if ((total % day) / hour != 0) {
            out << ' ' << (total % day) / hour << 'h';
        }
    }
    return out.str();
}

#ifndef WICUVANITY_HOST_TEST
__global__ void generator(
    const char* _needle,
    size_t needlesize,
    int in,
    bool case_sensitive,
    ChaChaSeed seed,
    uint64_t counter_base,
    int iterations,
    Match* results,
    unsigned int* result_count
) {
    int tid = threadIdx.x;
    uint64_t idx = static_cast<uint64_t>(blockIdx.x) * blockDim.x + tid;
    uint64_t thread_count = static_cast<uint64_t>(gridDim.x) * blockDim.x;

    extern __shared__ char needle[];

    if (tid < needlesize) {
        needle[tid] = case_sensitive ? _needle[tid] : cutolower(_needle[tid]);
    }

    __syncthreads();

    u8 privkey[32], pubkey[32];

    for (int iteration = 0; iteration < iterations; iteration++) {
        genpriv(privkey, seed, counter_base + idx + iteration * thread_count);
        genpub(privkey, pubkey);

        if (matches(pubkey, needle, needlesize, in, case_sensitive)) {
            unsigned int slot = atomicAdd(result_count, 1U);
    #pragma unroll
            for (int i = 0; i < 32; i++) {
                results[slot].private_key[i] = privkey[i];
                results[slot].public_key[i] = pubkey[i];
            }
        }
    }
}

int main(int argc, char** argv) {
    cxxopts::Options options(
        "wicuvanity",
        "Generate wireguard private and public keys with a specific public key prefix"
    );

    options.add_options()("needle", "needle to find", cxxopts::value<std::string>())
                       ("in", "needle in first ... characters", cxxopts::value<int>()->default_value("10"))
                       ("case-sensitive", "match capitalization exactly")
                       ("stats", "print the live generation rate and average ETA")
                       ("gridsize", "Manually set number of blocks. Requires --blocksize.", cxxopts::value<int>())
                       ("blocksize", "Manually set number of threads in block. Requires --gridsize.", cxxopts::value<int>())
                       ("h,help", "print usage");

    options.parse_positional({ "needle" });
    options.positional_help("needle");

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    if (!chacha20_self_test()) {
        std::cerr << "Error: ChaCha20 self-test failed" << std::endl;
        return 1;
    }

    if (!result.count("needle")) {
        std::cerr << "Error: needle is required" << std::endl;
        return 1;
    }

    auto needle = result["needle"].as<std::string>();
    int in = result["in"].as<int>();
    bool case_sensitive = result.count("case-sensitive") != 0;
    if (needle.empty()) {
        std::cerr << "Error: needle must not be empty" << std::endl;
        return 1;
    }
    if (!isBase64Needle(needle)) {
        std::cerr << "Error: needle must contain only base64 characters" << std::endl;
        return 1;
    }
    if (in < 1 || in > 44) {
        std::cerr << "Error: --in must be between 1 and 44" << std::endl;
        return 1;
    }
    if (needle.size() > static_cast<size_t>(in)) {
        std::cerr << "Error: needle cannot be longer than --in" << std::endl;
        return 1;
    }
    long double candidates_per_match = estimatedCandidatesPerMatch(needle, in, case_sensitive);
    if (!std::isfinite(candidates_per_match)) {
        std::cerr << "Error: needle cannot match an X25519 public key within --in " << in
                  << " (check base64 padding and final-character constraints)" << std::endl;
        return 1;
    }

    char* pndl_dev;
    cudaError_t code;

    int needlesize = needle.size(), gridsize, blocksize;

    if (result.count("gridsize") != result.count("blocksize")) {
        std::cerr << "Error: --gridsize and --blocksize must be specified together" << std::endl;
        return 1;
    }

    if (result.count("gridsize")) {
        gridsize = result["gridsize"].as<int>();
        blocksize = result["blocksize"].as<int>();
        if (gridsize < 1 || blocksize < 1) {
            std::cerr << "Error: --gridsize and --blocksize must be positive" << std::endl;
            return 1;
        }
    } else {
        int device;
        cudaDeviceProp properties;
        if (cudaSuccess != (code = cudaGetDevice(&device))
            || cudaSuccess != (code = cudaGetDeviceProperties(&properties, device)))
        {
            std::cerr << "Error: Querying GPU properties failed (" << cudaGetErrorString(code)
                      << ')' << std::endl;
            return 1;
        }

        int best_active_blocks = 0, best_active_threads = 0;
        for (int candidate = properties.warpSize; candidate <= properties.maxThreadsPerBlock;
             candidate += properties.warpSize)
        {
            if (candidate < needlesize) {
                continue;
            }

            int active_blocks;
            if (cudaSuccess
                != (code = cudaOccupancyMaxActiveBlocksPerMultiprocessor(
                        &active_blocks,
                        generator,
                        candidate,
                        needlesize
                    )))
            {
                std::cerr << "Error: Computing block size dynamically failed ("
                          << cudaGetErrorString(code) << "), try specifying it manually"
                          << std::endl;
                return 1;
            }

            int active_threads = active_blocks * candidate;
            if (active_threads > best_active_threads) {
                blocksize = candidate;
                best_active_blocks = active_blocks;
                best_active_threads = active_threads;
            }
        }

        if (best_active_blocks == 0) {
            std::cerr << "Error: no viable CUDA launch configuration" << std::endl;
            return 1;
        }
        gridsize = properties.multiProcessorCount * best_active_blocks;
    }

    if (blocksize < needlesize) {
        std::cerr << "Error: block size must be at least the needle size" << std::endl;
        return 1;
    }

    constexpr int max_batch_iterations = 32;
    constexpr uint64_t max_buffered_results = (64ULL * 1024 * 1024) / sizeof(Match);
    uint64_t thread_count = static_cast<uint64_t>(gridsize) * blocksize;
    int batch_iterations =
        std::clamp<uint64_t>(max_buffered_results / thread_count, 1, max_batch_iterations);
    uint64_t result_capacity_64 = thread_count * batch_iterations;
    if (result_capacity_64 > std::numeric_limits<unsigned int>::max()
        || result_capacity_64 > std::numeric_limits<size_t>::max() / sizeof(Match))
    {
        std::cerr << "Error: launch configuration is too large" << std::endl;
        return 1;
    }
    size_t result_capacity = static_cast<size_t>(result_capacity_64);

    if (cudaSuccess != (code = cudaMalloc(&pndl_dev, needlesize))) {
        std::cerr << "Error: Allocating needle on the GPU failed (" << cudaGetErrorString(code)
                  << ')' << std::endl;
        return 1;
    }
    if (cudaSuccess
        != (code = cudaMemcpy(pndl_dev, needle.data(), needlesize, cudaMemcpyHostToDevice)))
    {
        std::cerr << "Error: Copying needle to the GPU failed (" << cudaGetErrorString(code) << ')'
                  << std::endl;
        cudaFree(pndl_dev);
        return 1;
    }

    Match* results_dev;
    if (cudaSuccess != (code = cudaMalloc(&results_dev, result_capacity * sizeof(Match)))) {
        std::cerr << "Error: Allocating result buffer on the GPU failed ("
                  << cudaGetErrorString(code) << ')' << std::endl;
        cudaFree(pndl_dev);
        return 1;
    }

    unsigned int* result_count_dev;
    if (cudaSuccess != (code = cudaMalloc(&result_count_dev, sizeof(unsigned int)))) {
        std::cerr << "Error: Allocating result counter on the GPU failed ("
                  << cudaGetErrorString(code) << ')' << std::endl;
        cudaFree(results_dev);
        cudaFree(pndl_dev);
        return 1;
    }

    ChaChaSeed seed;
    arc4random_buf(&seed, sizeof(seed));

    std::signal(SIGINT, request_stop);
    std::signal(SIGTERM, request_stop);

    bool show_stats = result.count("stats") != 0;
    uint64_t counter_base = 0, interval_keys = 0;
    auto interval_start = std::chrono::steady_clock::now();
    std::vector<Match> results;
    code = cudaSuccess;

    while (!stop_requested) {
        if (cudaSuccess != (code = cudaMemset(result_count_dev, 0, sizeof(unsigned int)))) {
            break;
        }

        generator<<<gridsize, blocksize, needlesize>>>(
            pndl_dev,
            needlesize,
            in,
            case_sensitive,
            seed,
            counter_base,
            batch_iterations,
            results_dev,
            result_count_dev
        );
        code = cudaGetLastError();
        if (code != cudaSuccess) {
            break;
        }

        unsigned int result_count;
        if (cudaSuccess
            != (code = cudaMemcpy(
                    &result_count,
                    result_count_dev,
                    sizeof(result_count),
                    cudaMemcpyDeviceToHost
                )))
        {
            break;
        }
        if (result_count > result_capacity) {
            std::cerr << "Error: GPU result buffer overflow" << std::endl;
            code = cudaErrorUnknown;
            break;
        }

        if (result_count > 0) {
            results.resize(result_count);
            if (cudaSuccess
                != (code = cudaMemcpy(
                        results.data(),
                        results_dev,
                        result_count * sizeof(Match),
                        cudaMemcpyDeviceToHost
                    )))
            {
                break;
            }

            char private_b64[45], public_b64[45];
            for (const Match& match: results) {
                toBase64(match.private_key, private_b64);
                toBase64(match.public_key, public_b64);
                std::printf("private: %s | public: %s\n", private_b64, public_b64);
            }
            std::fflush(stdout);
        }

        counter_base += result_capacity_64;
        if (show_stats) {
            interval_keys += result_capacity_64;
            auto now = std::chrono::steady_clock::now();
            double seconds = std::chrono::duration<double>(now - interval_start).count();
            if (seconds >= 1.0) {
                double keys_per_second = interval_keys / seconds;
                std::cerr << '\r' << std::fixed << std::setprecision(2)
                          << "Rate: " << keys_per_second / 1'000'000.0 << " Mkey/s"
                          << " | Avg ETA: "
                          << formatDuration(candidates_per_match / keys_per_second) << std::flush;
                interval_keys = 0;
                interval_start = now;
            }
        }
    }

    if (show_stats) {
        std::cerr << std::endl;
    }
    cudaFree(result_count_dev);
    cudaFree(results_dev);
    cudaFree(pndl_dev);

    switch (code) {
        case cudaSuccess:
            return 0;
        case cudaErrorLaunchOutOfResources:
            std::cerr << "Error: out of resources. Try decreasing --blocksize to " << blocksize - 32
                      << std::endl;
            return 1;
        default:
            std::cerr << "Error: " << cudaGetErrorString(code) << std::endl;
            return 1;
    }
}
#endif
