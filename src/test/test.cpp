// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024-2025 Egor Pugin <egor.pugin@gmail.com>

#include <router_relay/router.h>

struct user_list_simple {
    std::unordered_map<std::string, user> users;

    void add_user(const std::string &name, const std::string &password) {
        users.emplace(name, user{// ul.users.size() + 1,
                                    name, password});
    }
    user &get_user(const std::string &name) {
        auto it = users.find(name);
        if (it == users.end()) {
            throw std::runtime_error{"no such user"};
        }
        auto &u = it->second;
        if (!u.flags[user::user_flags::enabled]) {
            throw std::runtime_error{"user is disabled"};
        }
        return u;
    }
};

struct host_manager_simple {
    using host_id = int64_t;
    using user_id = int64_t;
    struct host {
        struct key_type {
            host_id id{};
            uint8_t data[0x20];
        };

        host_id id;
        bytes key_{sizeof(key_type)};
        //peer p{};

        host(host_id id) : id{id} {
            key().id = id;
            rand_fill(key().data, std::size(key().data));
        }
        key_type &key() {
            return *(key_type *)key_.data();
        }
        bool operator==(const key_type &rhs) {
            return memcmp(&key(), &rhs, sizeof(key_type)) == 0;
        }
    };
    struct session {
        int64_t id{};
        int64_t rx{};
        int64_t tx{};
        bool stopped{};
    };
    host_id current_host_id{1};
    std::unordered_map<host_id, host> hosts;
    host_id current_session_id{1};
    std::unordered_map<int64_t, session> sessions;

    auto next_host_id() {
         return current_host_id++;
    }
    auto &new_host(auto &&addr) {
        auto hid = next_host_id();
        auto [it, _] = hosts.emplace(hid, host{hid});
        auto &h = it->second;
        return h;
    }
    host_id find_host(auto &&key, auto &&addr) {
        if (key.size() == sizeof(typename host::key_type)) {
            auto &k = *(typename host::key_type *)key.data();
            auto it = hosts.find(k.id);
            if (it != hosts.end() && it->second == k) {
                return it->first;
            }
        }
        return {};
    }
    session &start_session(host_id hid, const std::string &username, const std::string &hostaddr, const std::string &clientaddr) {
        return sessions[current_session_id++];
    }
    void end_session(auto sid) {
        sessions.erase(sid);
    }
    void set_offline(host_id id) {
        hosts.erase(id);
    }
};

int main(int argc, char *argv[]) {
    user_list_simple ul;
    host_manager_simple hm;
    ul.add_user("test", "test");

    boost::asio::io_context ctx;
    relay re{8070, hm};
    router ro{8060, ul, hm, re};
#ifndef NDEBUG
    ro.key = hex2bin("C0A067DDC31FBAE5FD9166234D5BC7AAF64BD73CFBF949F875DFB7145C2CF142"s);
#endif
    ro.start1(ctx);
    ctx.run();
    return 0;
}
