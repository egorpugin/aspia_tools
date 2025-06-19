// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2025 Egor Pugin <egor.pugin@gmail.com>

#pragma once

#include "helpers.h"
#include "srp_constants.h"

#include <boost/asio.hpp>
#include <google/protobuf/message_lite.h>
#include <proto/key_exchange.pb.h>
#include <proto/router_peer.pb.h>
#include <proto/relay_peer.pb.h>

#include <bitset>
#include <map>

using namespace std::literals;
namespace ip = boost::asio::ip;

template <typename T = void>
using task = boost::asio::awaitable<T>;

auto serialize(const google::protobuf::MessageLite &message) {
    bytes out;
    auto sz = message.ByteSizeLong();
    if (!sz) {
        throw std::runtime_error{"empty message"};
    }
    out.resize(sz);
    message.SerializeWithCachedSizesToArray(out);
    return out;
}
template <typename T>
auto deserialize(const auto &in) {
    T msg;
    if (!msg.ParseFromArray(in.data(), in.size())) {
        throw std::runtime_error{"bad message"};
    }
    return msg;
}

struct user {
    struct session {
        int64_t bytes;
        // time from, to
        // host id
    };
    enum user_flags {
        enabled = 0,
    };
    static inline constexpr int default_group = 8192;

    // user_id id;
    std::string name;
    //std::string password;
    bytes salt;
    int group{default_group};
    bytes verifier;
    std::bitset<32> flags{1 << user_flags::enabled};

    user() = default;
    user(
        // user_id id,
        const std::string &name, const std::string &password)
        //: id{id}
        : name{name}
        {
        salt.resize(64);
        rand_fill(salt);

        // https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
        bigint x = calc_x(salt, name, password);

        auto srp_pair = pair_by_group(group);
        bigint N = srp_pair.N;
        bigint g = srp_pair.g;

        openssl_ctx ctx = BN_CTX_new();
        bigint v;
        SSL_CHECK_FUNCTION(BN_mod_exp(v, g, x, N, ctx));
        verifier = v;
    }
};

// channel header
struct UserDataHeader {
    uint8_t channel_id;
    uint8_t reserved;
};

enum ServiceMessageType { KEEP_ALIVE = 1 };

enum KeepAliveFlags { KEEP_ALIVE_PONG = 0, KEEP_ALIVE_PING = 1 };

struct ServiceHeader {
    uint8_t type;      // Type of service packet (see ServiceDataType).
    uint8_t flags;     // Flags bitmask (depends on the type).
    uint8_t reserved1; // Reserved.
    uint8_t reserved2; // Reserved.
    uint32_t length;   // Additional data size.
};

struct router_relay_base {
    uint16_t port;

    task<> start(this auto &&obj) {
        auto ex = co_await boost::asio::this_coro::executor;
        ip::tcp::endpoint e{ip::make_address_v4("0.0.0.0"), obj.port};
        ip::tcp::acceptor a{ex, e};
        while (1) {
            auto s = co_await a.async_accept(boost::asio::use_awaitable);
            boost::asio::ip::tcp::no_delay option(true);
            boost::system::error_code error_code;
            s.set_option(option, error_code);
            boost::asio::co_spawn(ex, obj.handle_connection(std::move(s)), boost::asio::detached);
            /*[](auto eptr){
                if (eptr) {
                    try {
                        std::rethrow_exception(eptr);
                    } catch (std::exception &e) {
                        std::cerr << e.what() << "\n";
                    } catch (...) {
                        std::cerr << "unknown error\n";
                    }
                }
            }*/
        }
    }
    static task<std::string> receive_message(auto &s) {
    start:
        constexpr auto minlen = 4;
        uint8_t buffer[1+sizeof(ServiceHeader)];
        auto n = co_await s.async_read_some(boost::asio::buffer(buffer, minlen), boost::asio::use_awaitable);
        if (n < minlen) {
            throw std::runtime_error{"too small message"};
        }
        if (buffer[0] == 0) {
            // service message
            co_await boost::asio::async_read(s, boost::asio::buffer(buffer + minlen, sizeof(buffer) - minlen), boost::asio::use_awaitable);
            auto &sh = *(ServiceHeader*)&buffer[1];
            if (sh.type == KEEP_ALIVE) {
                sh.flags = !sh.flags; // ping->pong
                co_await s.async_send(boost::asio::buffer(buffer), boost::asio::use_awaitable);
                if (sh.length != 4) {
                    throw std::runtime_error{"bad packet"};
                }
                uint32_t data;
                co_await boost::asio::async_read(s, boost::asio::buffer(&data, sizeof(data)), boost::asio::use_awaitable);
                // send back the same
                co_await s.async_send(boost::asio::buffer(&data, sizeof(data)), boost::asio::use_awaitable);
            } else {
                throw std::runtime_error{"bad packet"};
            }
            goto start;
        }
        int sz_len{};
        int msg_length = buffer[sz_len] & 0x7F;
        if (buffer[sz_len++] & 0x80) {
            msg_length += (buffer[sz_len] & 0x7F) << 7;
            if (buffer[sz_len++] & 0x80) {
                msg_length += (buffer[sz_len] & 0x7F) << 14;
                if (buffer[sz_len++] & 0x80) {
                    msg_length += buffer[sz_len] << 21;
                }
            }
        }
        if (msg_length > 7 * 1024 * 1024) {
            throw std::runtime_error{"too big message"};
        }
        std::string in(msg_length, 0);
        memcpy(in.data(), buffer + sz_len, minlen - sz_len);
        auto to_read = msg_length - (minlen - sz_len);
        co_await boost::asio::async_read(s, boost::asio::buffer(in.data() + (minlen - sz_len), to_read), boost::asio::use_awaitable);
        co_return std::move(in);
    }
    template <typename T>
    static task<T> receive_message(auto &s) {
        auto msg = co_await receive_message(s);
        co_return deserialize<T>(msg);
    }
    template <typename T>
    static task<T> receive_message(auto &s, auto &&sesskey, auto &&iv) {
        auto msg = co_await receive_message(s);
        //
        chacha20_poly1305<0> dec{sesskey};
        std::string out(msg.size() - dec.tag_size(), 0);
        dec.decrypt(msg.data(), msg.size(), out.data(), iv);
        msg = std::move(out);
        //
        co_return deserialize<T>(msg);
    }
    static task<> send_message_raw(auto &s, auto &&msg) {
        int size = msg.size();
        char buf[4];
        int len{};
        buf[len++] = size & 0x7F;
        if (size > 0x7F) {
            buf[len - 1] |= 0x80;
            buf[len++] = size >> 7 & 0x7F;
            if (size > 0x3FFF) {
                buf[len - 1] |= 0x80;
                buf[len++] = size >> 14 & 0x7F;
                if (size > 0x1FFFF) {
                    buf[len - 1] |= 0x80;
                    buf[len++] = size >> 21 & 0xFF;
                }
            }
        }
        std::array<boost::asio::const_buffer, 2> buffers;
        buffers[0] = boost::asio::buffer(buf, len);
        buffers[1] = msg;
        co_await s.async_send(buffers, boost::asio::use_awaitable);
    }
    static task<> send_message(auto &s, const ::google::protobuf::MessageLite &msg) {
        auto out = serialize(msg);
        co_await send_message_raw(s, out);
    }
    static task<> send_message(auto &s, auto &msg, auto &&sesskey, auto &&iv) {
        auto out = serialize(msg);
        //
        chacha20_poly1305<1> enc{sesskey};
        auto x = out;
        x.resize(out.size() + enc.tag_size());
        enc.encrypt(out.data(), out.size(), x.data(), iv);
        out = std::move(x);
        //
        co_await send_message_raw(s, out);
    }
};

template <typename HostManager>
struct relay : router_relay_base {
    using key_id = int;
    struct key_data {
        key_id id;
        key_pair key;
        bytes decrypt_iv{12};
        std::optional<ip::tcp::socket> s;

        key_data() {
            rand_fill(decrypt_iv);
        }
        bool empty() const {
            return !s;
        }
        explicit operator bool() const {
            return !empty();
        }
    };
    struct pair {
        key_id k_host{};
        key_id k_client{};
        typename HostManager::host_id host_id{};
        std::string username;

        auto other(key_id k) {
            return k == k_host ? k_client : k_host;
        }
    };
    HostManager &hm;
    std::string address{"127.0.0.1"};
    key_id current_key_id{};
    std::unordered_map<key_id, key_data> key_pool;
    std::unordered_map<key_id, pair> pairs;

    auto &next() {
        auto &v = key_pool[++current_key_id];
        v.id = current_key_id;
        return v;
    }
    task<> handle_connection(ip::tcp::socket s) {
        auto ex = co_await boost::asio::this_coro::executor;
        auto sr = co_await receive_message<proto::PeerToRelay>(s);
        auto it = key_pool.find(sr.key_id());
        if (it == key_pool.end()) {
            co_return;
        }
        auto &k = it->second;
        if (!k.empty()) {
            throw std::runtime_error{"already set"};
        }
        auto sk = k.key.aspia_session_key(sr.public_key());
        chacha20_poly1305<0> dec{sk};
        auto secret = sr.data();
        std::string out;
        out.resize(secret.size() - dec.tag_size());
        // check that decrypt works
        dec.decrypt(secret.data(), secret.size(), out.data(), k.decrypt_iv);
        //auto ptrs = deserialize<proto::PeerToRelay::Secret>(out);
        k.s = std::move(s);
        auto &p = pairs.at(k.id);
        if (key_pool[p.other(k.id)]) {
            auto &sess = hm.start_session(p.host_id, p.username,
                key_pool[p.k_host].s->remote_endpoint().address().to_string(),
                key_pool[p.k_client].s->remote_endpoint().address().to_string()
            );
            auto sid = sess.id;

            // pair & pump now
            auto f = [&](auto id) {
                return [=](std::exception_ptr ptr) {
                    if (ptr) {
                        cleanup(id, sid);
                    }
                };
            };
            boost::asio::co_spawn(ex, pump(*key_pool[p.k_host].s, *key_pool[p.k_client].s, sess.rx, sess), f(k.id));
            boost::asio::co_spawn(ex, pump(*key_pool[p.k_client].s, *key_pool[p.k_host].s, sess.tx, sess), f(p.other(k.id)));
        } else {
            boost::asio::steady_timer timer{ex};
            timer.expires_after(10s);
            co_await timer.async_wait(boost::asio::use_awaitable);
            if (!key_pool[p.other(k.id)]) {
                cleanup(k.id, 0);
                cleanup(p.other(k.id), 0);
            }
        }
    }
    void cleanup(key_id id, auto sid) {
        auto it = pairs.find(id);
        if (it == pairs.end()) {
            return;
        }
        auto p = it->second;
        hm.end_session(sid);
        pairs.erase(id);
        if (pairs.contains(p.other(id))) {
            return;
        }
        key_pool.erase(id);
        key_pool.erase(p.other(id));
    }
    task<> pump(auto &s_from, auto &s_to, int64_t &bytes, auto &s) {
        // should be fine to pump more traffic per message
        // 1 pair of devices = 200KB
        // 1000 pairs = 200MB what is ok
        uint8_t buffer[100*1024];
        while (!s.stopped) {
            auto n = co_await s_from.async_read_some(boost::asio::buffer(buffer, sizeof(buffer)), boost::asio::use_awaitable);
            bytes += n;
            co_await s_to.async_send(boost::asio::buffer(buffer, n), boost::asio::use_awaitable);
        }
        s_from.close();
        s_to.close();
    }
    template <typename T>
    task<T> receive_message(auto &s) {
        uint32_t msg_length;
        auto n = co_await boost::asio::async_read(s, boost::asio::buffer(&msg_length, sizeof(msg_length)), boost::asio::use_awaitable);
        msg_length = std::byteswap(msg_length);
        std::string in(msg_length, 0);
        co_await boost::asio::async_read(s, boost::asio::buffer(in), boost::asio::use_awaitable);
        co_return deserialize<T>(in);
    }
};

template <typename UserManager, typename HostManager>
struct router : router_relay_base {
    struct peer {
        ip::tcp::socket *s;
        bytes *sesskey;
        bytes *encrypt_iv;
        bytes *decrypt_iv;

        explicit operator bool() const {
            return s;
        }
        task<> send_message(auto &msg) {
            co_await router_relay_base::send_message(*s, msg, *sesskey, *encrypt_iv);
        }
    };
    struct srp_data {
        std::string username;
        std::string sesskey;
    };

    UserManager &ul;
    HostManager &hm;
    relay<HostManager> &builtin_relay;
    key_pair key;
    std::map<typename HostManager::host_id, peer> online_hosts;

    void start1(boost::asio::io_context &ctx) {
        boost::asio::co_spawn(ctx, start(), boost::asio::detached);
        boost::asio::co_spawn(ctx, builtin_relay.start(), boost::asio::detached);
    }

    // https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
    task<srp_data> handle_srp(auto &s, auto &encrypt_iv, auto &decrypt_iv) {
        proto::ServerHello sh;
        sh.set_encryption(proto::ENCRYPTION_CHACHA20_POLY1305);
        co_await send_message(s, sh);

        auto srp = co_await receive_message<proto::SrpIdentify>(s);
        auto uname = srp.username();
        auto &&u = ul.get_user(uname);
        if (u.name.empty()) {
            throw std::runtime_error{"no such user"};
        }
        // on non existent user we may want to prevent timing attacks to hide user names?

        bytes bs(128);
        rand_fill(bs);
        bigint b = bs;

        auto srp_pair = pair_by_group(u.group);
        bigint N = srp_pair.N;
        bigint g = srp_pair.g;

        openssl_ctx ctx = BN_CTX_new();
        bigint gb;
        SSL_CHECK_FUNCTION(BN_mod_exp(gb, g, b, N, ctx));
        auto k = calc_k(N, g);
        bigint v = u.verifier;
        bigint kv;
        SSL_CHECK_FUNCTION(BN_mod_mul(kv, v, k, N, ctx));
        bigint B;
        SSL_CHECK_FUNCTION(BN_mod_add(B, gb, kv, N, ctx));

        proto::SrpServerKeyExchange srpserv;
        srpserv.set_iv(encrypt_iv);
        srpserv.set_salt(u.salt);
        srpserv.set_number(N);
        srpserv.set_generator(g);
        srpserv.set_b(B);
        co_await send_message(s, srpserv);

        auto srpclient = co_await receive_message<proto::SrpClientKeyExchange>(s);
        decrypt_iv = srpclient.iv();
        bigint A = srpclient.a();

        bigint result;
        SSL_CHECK_FUNCTION(BN_nnmod(result, A, N, ctx));
        if (BN_is_zero(result)) {
            throw std::runtime_error{"bad A"};
        }

        bigint tmp;
        SSL_CHECK_FUNCTION(BN_mod_exp(tmp, v, calc_xy(A, B, N), N, ctx));
        SSL_CHECK_FUNCTION(BN_mod_mul(tmp, A, tmp, N, ctx));

        bigint S;
        SSL_CHECK_FUNCTION(BN_mod_exp(S, tmp, b, N, ctx));

        auto sesskey = aspia_session_hash(S);
        co_return srp_data{uname, sesskey};
    }
    task<> handle_connection(ip::tcp::socket s) {
        auto ch = co_await receive_message<proto::ClientHello>(s);
        auto enc = ch.encryption();
        if (!(enc & proto::ENCRYPTION_CHACHA20_POLY1305)) {
            throw std::runtime_error{"unsupported enc"};
        }

        bytes decrypt_iv;
        bytes encrypt_iv(12);
        rand_fill(encrypt_iv);
        bytes sesskey;

        auto id = ch.identify();
        srp_data sd;
        if (id == proto::Identify::IDENTIFY_SRP) {
            sd = co_await handle_srp(s, encrypt_iv, decrypt_iv);
            sesskey = sd.sesskey;
        } else {
            if (ch.public_key().empty()) {
                throw std::runtime_error{"empty pubkey"};
            }
            if (ch.iv().empty()) {
                throw std::runtime_error{"empty iv"};
            }
            sesskey = key.aspia_session_key(ch.public_key());
            decrypt_iv = ch.iv();
            // dont care atm, but kick unsupported later
            //auto version = ch.version();

            proto::ServerHello sh;
            sh.set_encryption(proto::ENCRYPTION_CHACHA20_POLY1305);
            sh.set_iv(encrypt_iv);
            co_await send_message(s, sh);
        }

        // >= 2.6.0 with channels
        // not useful for router?
        auto channels_support = false;//ch.version().major() >= 2 && ch.version().minor() >= 6;

        proto::SessionChallenge sch;
        // minver 2.3.0
        // 2.6.0 has channels support
        // channels acce
        sch.mutable_version()->set_major(2);
        sch.mutable_version()->set_minor(channels_support ? 6 : 3);
        sch.mutable_version()->set_patch(0);
        sch.set_session_types(
            proto::RouterSession::ROUTER_SESSION_HOST |
            proto::RouterSession::ROUTER_SESSION_CLIENT);
        /*sch.set_cpu_cores(0);
        sch.set_os_name("");
        sch.set_computer_name("");
        sch.set_arch("");*/
        sch.set_display_name("generic aspia router");
        co_await send_message(s, sch, sesskey, encrypt_iv);

        auto sr = co_await receive_message<proto::SessionResponse>(s, sesskey, decrypt_iv);
        auto session_type = sr.session_type();
        if (session_type != proto::RouterSession::ROUTER_SESSION_HOST &&
            session_type != proto::RouterSession::ROUTER_SESSION_CLIENT) {
            co_return;
        }

        switch (session_type) {
        case proto::RouterSession::ROUTER_SESSION_HOST: {
            typename HostManager::host_id hid{};
            try {
                co_await handle_host(std::move(s), sesskey, encrypt_iv, decrypt_iv, hid);
            } catch (std::exception &e) {
                std::cerr << e.what() << "\n";
            }
            online_hosts.erase(hid);
            hm.set_offline(hid);
            break;
        }
        case proto::RouterSession::ROUTER_SESSION_CLIENT:
            co_await handle_client(std::move(s), sesskey, encrypt_iv, decrypt_iv, sd);
            break;
        }
    }

    task<> handle_host(auto &&s, auto &&sesskey, auto &&encrypt_iv, auto &&decrypt_iv, auto &hid) {
        while (1) {
            auto ptr = co_await receive_message<proto::PeerToRouter>(s, sesskey, decrypt_iv);
            proto::RouterToPeer rtp;
            if (ptr.has_host_id_request()) {
                auto &req = ptr.host_id_request();
                if (req.type() & proto::HostIdRequest::Type::HostIdRequest_Type_NEW_ID) {
                    auto &&h = hm.new_host(s.remote_endpoint().address().to_string());
                    hid = h.id;
                    online_hosts[h.id] = peer{&s, &sesskey, &encrypt_iv, &decrypt_iv};
                    auto &hidr = *rtp.mutable_host_id_response();
                    hidr.set_host_id(h.id);
                    hidr.set_key(h.key_);
                    hidr.set_error_code(proto::HostIdResponse::ErrorCode::HostIdResponse_ErrorCode_SUCCESS);
                } else if (req.type() & proto::HostIdRequest::Type::HostIdRequest_Type_EXISTING_ID) {
                    auto &hidr = *rtp.mutable_host_id_response();
                    hidr.set_error_code(proto::HostIdResponse::ErrorCode::HostIdResponse_ErrorCode_NO_HOST_FOUND);
                    if (auto hid2 = hm.find_host(req.key(), s.remote_endpoint().address().to_string())) {
                        hid = hid2;
                        online_hosts[hid] = peer{&s, &sesskey, &encrypt_iv, &decrypt_iv};
                        hidr.set_host_id(hid);
                        hidr.set_key(req.key());
                        hidr.set_error_code(proto::HostIdResponse::ErrorCode::HostIdResponse_ErrorCode_SUCCESS);
                    }
                } else if (req.type() & proto::HostIdRequest::Type::HostIdRequest_Type_UNKNOWN) {
                    auto &hidr = *rtp.mutable_host_id_response();
                    hidr.set_error_code(proto::HostIdResponse::ErrorCode::HostIdResponse_ErrorCode_UNKNOWN);
                }
            } else if (ptr.has_reset_host_id()) {
                continue; // no response, because we need authorization to do it!!!
            } else {
                co_return; // close on unknown
            }
            co_await send_message(s, rtp, sesskey, encrypt_iv);
        }
    }
    task<> handle_client(auto &&s, auto &&sesskey, auto &&encrypt_iv, auto &&decrypt_iv, auto &srp) {
        // we need a loop here for console and check host status
        bool stop{};
        while (!stop) {
            auto ptr = co_await receive_message<proto::PeerToRouter>(s, sesskey, decrypt_iv);
            proto::RouterToPeer rtp;
            if (ptr.has_connection_request()) {
                auto id = ptr.connection_request().host_id();
                if (online_hosts.contains(id)) {
                    auto &co = *rtp.mutable_connection_offer();
                    co.set_error_code(proto::ConnectionOffer::ErrorCode::ConnectionOffer_ErrorCode_SUCCESS);
                    co.mutable_host_data()->set_host_id(id);
                    auto &r = *co.mutable_relay();
                    r.set_host(builtin_relay.address);
                    r.set_port(builtin_relay.port);
                    proto::PeerToRelay::Secret secret;
                    //secret.set_client_address();
                    secret.set_client_user_name(srp.username);
                    //secret.set_client_host_address();
                    secret.set_host_id(id);
                    r.set_secret(serialize(secret));
                    auto &rk = *r.mutable_key();
                    rk.set_type(proto::RelayKey::Type::RelayKey_Type_TYPE_X25519);
                    rk.set_encryption(proto::RelayKey::Encryption::RelayKey_Encryption_ENCRYPTION_CHACHA20_POLY1305);
                    // relay data
                    typename std::remove_reference_t<decltype(builtin_relay)>::pair p;
                    p.host_id = id;
                    p.username = srp.username;
                    // host data
                    {
                        auto &k = builtin_relay.next();
                        p.k_host = k.id;
                        rk.set_key_id(k.id);
                        rk.set_public_key(k.key.pubkey);
                        rk.set_iv(k.decrypt_iv);
                        co.set_peer_role(proto::ConnectionOffer::PeerRole::ConnectionOffer_PeerRole_HOST);
                        co_await online_hosts[id].send_message(rtp);
                    }
                    // client data
                    {
                        auto &k = builtin_relay.next();
                        p.k_client = k.id;
                        rk.set_key_id(k.id);
                        rk.set_public_key(k.key.pubkey);
                        rk.set_iv(k.decrypt_iv);
                        co.set_peer_role(proto::ConnectionOffer::PeerRole::ConnectionOffer_PeerRole_CLIENT);
                    }
                    builtin_relay.pairs[p.k_host] = p;
                    builtin_relay.pairs[p.k_client] = p;
                } else {
                    auto &co = *rtp.mutable_connection_offer();
                    co.set_error_code(proto::ConnectionOffer::ErrorCode::ConnectionOffer_ErrorCode_PEER_NOT_FOUND);
                }
                //stop = true;
            } else if (ptr.has_check_host_status()) {
                rtp.mutable_host_status()->set_status(online_hosts.contains(ptr.check_host_status().host_id())
                    ? proto::HostStatus::Status::HostStatus_Status_STATUS_ONLINE
                    : proto::HostStatus::Status::HostStatus_Status_STATUS_OFFLINE
                );
            } else {
                co_return; // close on unknown message
            }
            co_await send_message(s, rtp, sesskey, encrypt_iv);
        }
    }
};
