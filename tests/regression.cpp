#define WICUVANITY_HOST_TEST
#define __host__
#define __device__
#define __forceinline__ inline
#include "../main.cu"
#undef __forceinline__
#undef __device__
#undef __host__

#include <array>
#include <memory>
#include <openssl/evp.h>
#include <random>
#include <string_view>
#include <utility>

using Key = std::array<u8, 32>;

void check(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << std::endl;
        std::exit(EXIT_FAILURE);
    }
}

Key clamped(Key key) {
    key[0] &= 248;
    key[31] = (key[31] & 63) | 64;
    return key;
}

Key fromHex(std::string_view hex) {
    check(hex.size() == 64, "invalid test vector length");
    Key out;
    for (size_t i = 0; i < out.size(); i++) {
        out[i] = std::stoul(std::string(hex.substr(2 * i, 2)), nullptr, 16);
    }
    return out;
}

Key opensslPublicKey(const Key& private_key) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519,
            nullptr,
            private_key.data(),
            private_key.size()
        ),
        EVP_PKEY_free
    );
    check(key != nullptr, "OpenSSL X25519 initialization");
    Key out;
    size_t size = out.size();
    check(EVP_PKEY_get_raw_public_key(key.get(), out.data(), &size) == 1, "OpenSSL public key");
    check(size == out.size(), "OpenSSL public key length");
    return out;
}

void storeLittleEndian(u8* out, uint32_t word) {
    for (int i = 0; i < 4; i++) {
        out[i] = word >> (8 * i);
    }
}

Key opensslPrivateKey(const ChaChaSeed& seed, uint64_t counter) {
    Key key;
    for (int i = 0; i < 8; i++) {
        storeLittleEndian(key.data() + 4 * i, seed.key[i]);
    }
    std::array<u8, 16> iv;
    storeLittleEndian(iv.data(), static_cast<uint32_t>(counter));
    storeLittleEndian(iv.data() + 4, seed.nonce[0] ^ static_cast<uint32_t>(counter >> 32));
    storeLittleEndian(iv.data() + 8, seed.nonce[1]);
    storeLittleEndian(iv.data() + 12, seed.nonce[2]);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free
    );
    check(context != nullptr, "OpenSSL ChaCha20 context");
    check(
        EVP_EncryptInit_ex(context.get(), EVP_chacha20(), nullptr, key.data(), iv.data()) == 1,
        "OpenSSL ChaCha20 initialization"
    );
    Key zero = {}, out;
    int size = 0;
    check(
        EVP_EncryptUpdate(context.get(), out.data(), &size, zero.data(), zero.size()) == 1,
        "OpenSSL ChaCha20 block"
    );
    check(size == static_cast<int>(out.size()), "OpenSSL ChaCha20 output length");
    return clamped(out);
}

void testPrivateKeys() {
    check(chacha20_self_test(), "RFC 8439 ChaCha20 vector");
    std::mt19937_64 random(8439);
    const uint64_t boundaries[] = {
        0, 1, (1ULL << 32) - 1, 1ULL << 32, (1ULL << 32) + 1, std::numeric_limits<uint64_t>::max(),
    };
    for (int sample = 0; sample < 8; sample++) {
        ChaChaSeed seed;
        for (uint32_t& word: seed.key) {
            word = random();
        }
        for (uint32_t& word: seed.nonce) {
            word = random();
        }
        auto verify = [&](uint64_t counter) {
            Key actual;
            genpriv(actual.data(), seed, counter);
            check(actual == opensslPrivateKey(seed, counter), "independent ChaCha20 candidate");
            check(actual == clamped(actual), "candidate clamping");
        };
        for (uint64_t counter: boundaries) {
            verify(counter);
        }
        for (uint64_t counter = 0; counter < 64; counter++) {
            verify(counter);
        }
    }
}

void testPublicKeys() {
    const std::array<std::pair<Key, Key>, 2> vectors = { {
        {
            fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
            fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
        },
        {
            fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
            fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
        },
    } };
    for (const auto& [private_key, expected]: vectors) {
        Key key = clamped(private_key), actual;
        genpub(key.data(), actual.data());
        check(actual == expected, "RFC 7748 public key");
    }

    auto verify = [](Key key) {
        Key expected = opensslPublicKey(key), actual;
        key = clamped(key);
        genpub(key.data(), actual.data());
        check(actual == expected, "X25519 differential test");
    };
    Key key = {};
    verify(key);
    key.fill(255);
    verify(key);
    for (int bit = 0; bit < 256; bit++) {
        key.fill(0);
        key[bit / 8] = 1 << (bit % 8);
        verify(key);
    }
    std::mt19937_64 random(7748);
    for (int sample = 0; sample < 1024; sample++) {
        for (u8& byte: key) {
            byte = random();
        }
        verify(key);
    }
}

std::string lowercase(std::string text) {
    for (char& c: text) {
        if (c >= 'A' && c <= 'Z') {
            c += 'a' - 'A';
        }
    }
    return text;
}

void testBase64() {
    std::mt19937_64 random(4648);
    for (int last_byte = 0; last_byte < 256; last_byte++) {
        Key key;
        for (u8& byte: key) {
            byte = random();
        }
        key[31] = last_byte;
        std::array<u8, 45> encoded;
        check(EVP_EncodeBlock(encoded.data(), key.data(), key.size()) == 44, "OpenSSL Base64");
        std::string expected(reinterpret_cast<const char*>(encoded.data()));
        char actual[45];
        toBase64(key.data(), actual);
        check(actual == expected, "Base64 encoding");
        for (int position = 0; position < 44; position++) {
            check(base64_char_at(key.data(), position) == expected[position], "Base64 boundary");
        }

        for (int window: { 1, 10, 41, 42, 43, 44 }) {
            std::vector<std::string> needles = {
                expected,
                expected.substr(0, window),
                expected.substr(window - 1, 1),
                expected.substr(41),
                expected.substr(42),
                "=",
                "==",
                "A=",
                "c=",
                "aB",
                "/+",
            };
            for (bool sensitive: { false, true }) {
                std::string haystack = expected.substr(0, window);
                if (!sensitive) {
                    haystack = lowercase(haystack);
                }
                for (std::string needle: needles) {
                    if (!sensitive) {
                        needle = lowercase(needle);
                    }
                    bool found = haystack.find(needle) != std::string::npos;
                    check(
                        matches(key.data(), needle.data(), needle.size(), window, sensitive)
                            == found,
                        "Base64 substring matching"
                    );
                }
            }
        }
    }
}

void checkOdds(const std::string& needle, int in, bool sensitive, long double expected) {
    long double actual = estimatedCandidatesPerMatch(needle, in, sensitive);
    bool correct =
        std::isinf(expected) ? std::isinf(actual) : std::fabs(actual / expected - 1.0L) < 1e-14L;
    check(correct, "incorrect search odds for " + needle + " within " + std::to_string(in));
}

void testSearchOdds() {
    long double impossible = std::numeric_limits<long double>::infinity();
    checkOdds("Hayza", 5, false, std::pow(32.0L, 5));
    checkOdds("Hayza", 5, true, std::pow(64.0L, 5));
    checkOdds("=", 10, false, impossible);
    checkOdds("=", 43, true, impossible);
    checkOdds("=", 44, false, 1);
    checkOdds("=", 44, true, 1);
    checkOdds("A=", 2, false, impossible);
    checkOdds("=A", 44, false, impossible);
    checkOdds("==", 44, false, impossible);
    checkOdds("A=", 44, true, 16);
    checkOdds("A=", 44, false, 16);
    checkOdds("B=", 44, false, impossible);
    checkOdds("C=", 44, true, impossible);
    checkOdds("C=", 44, false, 16);
    checkOdds("AA=", 44, true, 512);
    checkOdds("IA=", 44, true, impossible);
    checkOdds("IA=", 44, false, 512);
    checkOdds(std::string(41, 'A') + 'I', 42, true, impossible);
    checkOdds(std::string(41, 'A') + 'I', 42, false, std::pow(32.0L, 42));
    checkOdds(std::string(42, 'A') + 'B', 43, false, impossible);
    checkOdds(std::string(43, 'A'), 43, true, std::ldexp(1.0L, 255));
    checkOdds(std::string(43, 'A'), 43, false, std::ldexp(1.0L, 214));
    checkOdds(std::string(43, 'A') + '=', 44, true, std::ldexp(1.0L, 255));
    checkOdds(std::string(44, 'A'), 44, false, impossible);
    checkOdds("A", 44, true, 1 / (1 - std::pow(63.0L / 64, 41) * (31.0L / 32) * (15.0L / 16)));
    checkOdds("a", 44, false, 1 / (1 - std::pow(31.0L / 32, 42) * (15.0L / 16)));
}

int main() {
    testPrivateKeys();
    testPublicKeys();
    testBase64();
    testSearchOdds();
    std::cout << "ChaCha20, X25519, Base64 matching, and search-odds regressions passed"
              << std::endl;
}
