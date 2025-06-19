// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include <boost/asio/buffer.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <format>
#include <string>
#include <variant>

#define SSL_CHECK(x) do {if (!(x)) {throw std::runtime_error{"error during: " #x};}} while(0)
#define SSL_CHECK_FUNCTION(x) do {if (x != 1) {throw std::runtime_error{"error during: " #x};}} while(0)

struct bytes {
    uint8_t *data_{};
    int len{};

    bytes(){}
    bytes(int n){len=n; data_ = (uint8_t *)malloc(len);}
    bytes(const bytes &in) {
        operator=(in);
    }
    bytes &operator=(const bytes &in) {
        this->~bytes();
        len = in.len; data_ = (uint8_t *)malloc(len);
        memcpy(data_, in.data_, len);
        return *this;
    }
    bytes(bytes &&in) {
        operator=(std::move(in));
    }
    bytes &operator=(bytes &&in) {
        this->~bytes();
        len = in.len;
        data_ = in.data_;
        in.len = 0;
        in.data_ = nullptr;
        return *this;
    }
    bytes &operator=(const std::string &s) {
        this->~bytes();
        len=s.size(); data_ = (uint8_t *)malloc(len);
        memcpy(data_, s.data(), s.size());
        return *this;
    }
    ~bytes(){free(data_);}
    operator uint8_t*() const {return data_;}
    operator int() const {return len;}
    operator std::string() const {return empty() ? std::string{} : std::string(data_, data_+len);}
    operator boost::asio::const_buffer() const {return boost::asio::const_buffer(data_, len);}
    bool empty() const { return len == 0; }
    auto data() const {return data_;}
    auto size() const {return len;}
    void resize(int n) {len = n;data_ = (uint8_t *)realloc(data_, len);}
    auto &operator[](int n) {return data_[n];}
    bool operator==(const auto &s) const {
        if (size() != s.size()) {
            return false;
        }
        return memcmp(data_, s.data(), s.size()) == 0;
    }
    auto begin() {return data_;}
    auto end() {return data_+len;}
};

struct bigint {
    BIGNUM *b;

    bigint() {b = BN_new();}
    bigint(BIGNUM *in) : b{in} {}
    bigint(const std::string &in) {
        operator=(in);
    }
    bigint(const std::string_view &in) {
        operator=(in);
    }
    bigint(const bytes &in) {
        operator=(in);
    }
    bigint(const bigint &) = delete;
    bigint &operator=(const bigint &) = delete;
    bigint(bigint &&in) {
        operator=(std::move(in));
    }
    bigint &operator=(bigint &&in) {
        this->~bigint();
        b = in.b;
        in.b = nullptr;
        return *this;
    }
    bigint &operator=(BIGNUM *in) {b = in;return *this;}
    bigint &operator=(const std::string &in) {
        b = BN_bin2bn((uint8_t *)in.data(), in.size(), nullptr);
        return *this;
    }
    bigint &operator=(const std::string_view &in) {
        b = BN_bin2bn((uint8_t *)in.data(), in.size(), nullptr);
        return *this;
    }
    bigint &operator=(const bytes &in) {
        b = BN_bin2bn((uint8_t *)in.data(), in.size(), nullptr);
        return *this;
    }
    ~bigint() {BN_free(b);}
    operator BIGNUM*() const {return b;}
    operator std::string() const {
        int length = BN_num_bytes(b);
        std::string s(length, 0);
        BN_bn2bin(b, (uint8_t *)s.data());
        return s;
    }
};

template <>
struct std::formatter<bytes> : formatter<std::string> {
    auto format(const bytes &p, format_context &ctx) const {
        return std::formatter<std::string>::format(p, ctx);
    }
};

template <auto f>
auto hash(const std::string &data) {
    uint8_t hash[EVP_MAX_MD_SIZE];
    uint32_t hash_size;
    EVP_Digest(data.data(), data.size(), hash, &hash_size, f(), nullptr);
    return std::string(hash, hash + hash_size);
}
auto aspia_session_hash(const auto &data) {
    return hash<EVP_blake2s256>(data);
}
auto hex2bin(auto key) {
    for (int i = 0, j = 0; i < key.size(); i += 2) {
        auto h2b = [](auto c) {
            if (c >= 'A' && c <= 'F') {
                return c - 'A' + 10;
            }
            if (c >= 'a' && c <= 'f') {
                return c - 'a' + 10;
            }
            if (c >= '0' && c <= '9') {
                return c - '0';
            }
            throw std::runtime_error{"bad digit16"};
        };
        key[j++] = (h2b(key[i]) << 4) + h2b(key[i + 1]);
    }
    key.resize(key.size() / 2);
    return key;
}
auto bin2hex(auto &&key) {
    constexpr char alph[] = "0123456789ABCDEF";
    std::string s;
    for (uint8_t c : key) {
        s += alph[c >> 4];
        s += alph[c & 0xF];
    }
    return s;
}
void inc_counter(bytes &counter) {
    for (int i = counter.size() - 1; i >= 0; i--) {
        if (++counter[i] != 0)
            break;
    }
}
void rand_fill(uint8_t *s, auto len) {
    SSL_CHECK_FUNCTION(RAND_bytes(s, len));
}
void rand_fill(bytes &s) {
    rand_fill(s.data(), s.size());
}
auto calc_xy(auto &&x, auto &&y, auto &&N) {
    if (x != N && BN_ucmp(x, N) >= 0) {
        throw std::runtime_error{"BN_ucmp err"};
    }
    if (y != N && BN_ucmp(y, N) >= 0) {
        throw std::runtime_error{"BN_ucmp err"};
    }
    int N_bytes = BN_num_bytes(N);
    auto xy_size = N_bytes * 2;
    std::string xy(xy_size, 0);
    if (BN_bn2binpad(x, (uint8_t *)xy.data(), N_bytes) < 0) {
        throw std::runtime_error{"BN err"};
    }
    if (BN_bn2binpad(y, (uint8_t *)xy.data() + N_bytes, N_bytes) < 0) {
        throw std::runtime_error{"BN err"};
    }
    auto ks = hash<EVP_blake2b512>(xy);
    bigint k = BN_bin2bn((uint8_t *)ks.data(), ks.size(), nullptr);
    return k;
}
auto calc_x(auto &&s, auto &&I, auto &&p) {
    return hash<EVP_blake2b512>(std::format("{}{}", s, hash<EVP_blake2b512>(std::format("{}:{}", I, p))));
}
auto calc_k(auto &&N, auto &&g) {
    return calc_xy(N, g, N);
}

struct openssl_ctx {
    struct empty {};
    using ctx_type = std::variant<empty, EVP_PKEY*, EVP_PKEY_CTX*, EVP_CIPHER_CTX*, BN_CTX*>;
    ctx_type ctx;

    openssl_ctx(){}
    openssl_ctx(auto *p) {
        operator=(p);
    }
    openssl_ctx &operator=(auto *p) {
        if (p == nullptr) {
            throw std::runtime_error{"openssl error"};
        }
        this->~openssl_ctx();
        ctx = p;
        return *this;
    }
    openssl_ctx(const openssl_ctx &) = delete;
    openssl_ctx &operator=(const openssl_ctx &) = delete;
    ~openssl_ctx() {
        switch (ctx.index()) {
        case 1:
            EVP_PKEY_free(*this);
            break;
        case 2:
            EVP_PKEY_CTX_free(*this);
            break;
        case 3:
            EVP_CIPHER_CTX_free(*this);
            break;
        case 4:
            BN_CTX_free(*this);
            break;
        default:
            break;
        }
    }
    template <typename T> operator T*() const { return std::get<T*>(ctx); }
    template <typename T> operator const T*() const { return std::get<T*>(ctx); }
    explicit operator bool() const {
        return ctx.index();
    }
};

struct key_pair {
    std::string pkey;
    std::string pubkey;

    key_pair() {
        openssl_ctx ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        SSL_CHECK_FUNCTION(EVP_PKEY_keygen_init(ctx));
        EVP_PKEY *private_key = nullptr;
        SSL_CHECK_FUNCTION(EVP_PKEY_keygen(ctx, &private_key));
        pkey.resize(0x20, 0);
        auto key_length = pkey.size();
        SSL_CHECK_FUNCTION(EVP_PKEY_get_raw_private_key(private_key, (uint8_t *)pkey.data(), &key_length));

        pubkey = public_key();
    }
    key_pair(const std::string &pkey) : pkey{pkey} {
        pubkey = public_key();
    }
    std::string public_key() {
        openssl_ctx pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, (uint8_t*)pkey.data(), pkey.size());
        std::string public_key(0x20, 0);
        auto public_key_length = public_key.size();
        SSL_CHECK_FUNCTION(EVP_PKEY_get_raw_public_key(pkey_, (uint8_t*)public_key.data(), &public_key_length));
        return public_key;
    }
    auto session_key(const std::string &peer_public_key) {
        openssl_ctx public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, (uint8_t *)peer_public_key.data(),
                                                      peer_public_key.size());
        openssl_ctx pkey_ = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, (uint8_t *)pkey.data(), pkey.size());
        openssl_ctx ctx = EVP_PKEY_CTX_new(pkey_, nullptr);
        SSL_CHECK_FUNCTION(EVP_PKEY_derive_init(ctx));
        SSL_CHECK_FUNCTION(EVP_PKEY_derive_set_peer(ctx, public_key));
        std::string session_key(0x20, 0);
        auto session_key_length = session_key.size();
        SSL_CHECK_FUNCTION(EVP_PKEY_derive(ctx, (uint8_t*)session_key.data(), &session_key_length));
        return session_key;
    }
    auto aspia_session_key(const std::string &peer_public_key) {
        auto sk = session_key(peer_public_key);
        return aspia_session_hash(sk);
    }
};

template <auto f, int Encrypt, int key_size, int iv_size, int TagSize>
struct openssl_encdec {
    static consteval auto tag_size() {return TagSize;}

    openssl_ctx ctx;

    openssl_encdec(auto &&key) {
        ctx = EVP_CIPHER_CTX_new();
        SSL_CHECK_FUNCTION(EVP_CipherInit_ex(ctx, f(), nullptr, nullptr, nullptr, Encrypt));
        SSL_CHECK_FUNCTION(EVP_CIPHER_CTX_set_key_length(ctx, key_size));
        SSL_CHECK_FUNCTION(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_size, nullptr));
        SSL_CHECK_FUNCTION(EVP_CipherInit_ex(ctx, nullptr, nullptr, (uint8_t*)key.data(), nullptr, Encrypt));
    }

    void encrypt(auto &&in, auto in_size, auto &&out, auto &iv) requires (Encrypt == 1) {
        SSL_CHECK_FUNCTION(EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, (uint8_t*)iv.data()));
        int length;
        SSL_CHECK_FUNCTION(EVP_EncryptUpdate(ctx, reinterpret_cast<uint8_t *>(out) + tag_size(), &length,
                              reinterpret_cast<const uint8_t *>(in), static_cast<int>(in_size)));
        SSL_CHECK_FUNCTION(EVP_EncryptFinal_ex(ctx, reinterpret_cast<uint8_t *>(out) + tag_size() + length, &length));
        SSL_CHECK_FUNCTION(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_size(), out));
        inc_counter(iv);
    }
    void decrypt(auto &&in, auto in_size, auto &&out, auto &iv) requires (Encrypt == 0) {
        SSL_CHECK_FUNCTION(EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, (uint8_t *)iv.data()));
        int length;
        SSL_CHECK_FUNCTION(EVP_DecryptUpdate(ctx, reinterpret_cast<uint8_t *>(out), &length,
                              reinterpret_cast<const uint8_t *>(in) + tag_size(),
                              static_cast<int>(in_size) - tag_size()));
        SSL_CHECK_FUNCTION(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag_size(), reinterpret_cast<uint8_t *>(in)));
        SSL_CHECK_FUNCTION(EVP_DecryptFinal_ex(ctx, reinterpret_cast<uint8_t *>(out) + length, &length));
        inc_counter(iv);
    }
};
template <int Encrypt>
struct chacha20_poly1305 : openssl_encdec<&EVP_chacha20_poly1305, Encrypt, 32, 12, 16> {
    using base = openssl_encdec<&EVP_chacha20_poly1305, Encrypt, 32, 12, 16>;
    using base::base;
};
