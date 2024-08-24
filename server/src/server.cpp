#include "../server.h"
#include "../message.h"
#include <stdexcept>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include "../base64.h"

using json = nlohmann::json;

// util
std::string get_uuid() {
    static std::random_device dev;
    static std::mt19937 rng(dev());

    std::uniform_int_distribution<int> dist(0, 15);

    const char *v = "0123456789abcdef";
    const bool dash[] = { 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0 };

    std::string res;
    for (int i = 0; i < 16; i++) {
        if (dash[i]) res += "-";
        res += v[dist(rng)];
        res += v[dist(rng)];
    }
    return res;
}

// Server
std::string Server::hash(const std::string& content) {
    EVP_MD_CTX*   context = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_md5();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int  md_len;
    std::string   output;

    EVP_DigestInit_ex2(context, md, NULL);
    EVP_DigestUpdate(context, content.c_str(), content.length());
    EVP_DigestFinal_ex(context, md_value, &md_len);
    EVP_MD_CTX_free(context);

    output.resize(md_len * 2);
    for (unsigned int i = 0 ; i < md_len ; ++i)
      std::sprintf(&output[i * 2], "%02x", md_value[i]);
    return output;
}

std::pair<std::string, std::string> Server::parse_auth(const std::string& auth) {
    if(!auth.find("Basic ") == 0)
        throw std::runtime_error("Invalid Authorization type");
    std::string decoded = base64_decode(auth.substr(6));
    size_t colon = decoded.find(":");
    if(colon == std::string::npos)
        throw std::runtime_error("Invalid Authorization header");

    return {decoded.substr(0, colon), decoded.substr(colon + 1)};
}

bool Server::auth_user(const std::string& username, const std::string& password) {
    return db.get_user_hash(username) == hash(password);
}

bool Server::is_user_in_group(const std::string& username, int groupid) {
    bool found{};
    for(const auto& [id, name] : db.get_user_groups(username))
        if(id == groupid) { found = true; break; }
    return found;
}

Server::Server(const std::string& data_dir) : db(data_dir) {
    set_base_dir(data_dir.c_str());

    // USER ACCOUNT INTERACTIONS
    Post("/register", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            db.create_user(username, hash(password));
            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Get("/verify_creds", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            res.status = auth_user(username, password) ? 200 : 401;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Post("/add_key", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }

            if(!req.has_header("keyid")) { res.status = 400; return; }
            db.add_key(username, req.get_header_value("keyid"), req.body);
            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Get("/contacts", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }

            auto contacts{db.get_contacts(username)};
            json contacts_json(json::value_t::array);
            for(const auto& contact : contacts) {
                contacts_json.push_back(contact);
            }
            res.set_content(contacts_json.dump(), "application/json");
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });
    Put("/contacts", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }

            db.add_contact(username, req.body);
            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    // MESSAGE INTERACTIONS
    Get("/users/:username/messages", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            auto messages{db.get_direct_messages(req.path_params.at("username"), username)};
            json messages_json(json::value_t::array);
            for(const auto& message : messages)
                messages_json.push_back({
                    {"from", message.from},
                    {"to", message.to},
                    {"timestamp", message.timestamp},
                    {"content", message.content},
                    {"decryption_key", message.decryption_key}
                });
            res.set_content(messages_json.dump(), "application/json");
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });
    Post("/users/:username/messages", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            json data{ json::parse(req.body) };
            data = data.at(0);

            TextMessage message {
                DIRECT, username, data.at("to"),
                (int)std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count(),
                data.at("decryption_key"),
                data.at("content")
            };
            db.add_direct_message(message);
            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });
    Post("/users/:username/files", [&](const httplib::Request& req, httplib::Response& res, const httplib::ContentReader &content_reader) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }
        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            if(!req.has_header("filename")) { res.status = 400; return; }

            std::string localname{get_uuid()}, decryption_key;
            std::ofstream filestream{"data/files/"+localname};
            content_reader(
                [&](const char *data, size_t data_length) {
                    if(data_length > 1) {
                        decryption_key = std::string(data, data_length);
                        return true;
                    }
                    filestream.write(data, data_length);
                    return true;
                }
            );
            filestream.close();
            
            File file {
                DIRECT, username, req.path_params.at("username"),
                (int)std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count(),
                decryption_key,
                req.get_header_value("filename"),
                localname
            };
            db.register_file(file);

            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Get("/users/:username/files", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }
        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            auto files{db.get_files(req.path_params.at("username"), username)};
            json files_json(json::value_t::array);
            for(const auto& file : files)
                files_json.push_back({
                    {"from", file.from},
                    {"to", file.to},
                    {"timestamp", file.timestamp},
                    {"filename", file.filename},
                    {"remote_filename", file.localname},
                    {"decryption_key", file.decryption_key}
                });
            res.set_content(files_json.dump(), "application/json");
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    // KEY INTERACTIONS
    Get("/users/:username/pubkeys", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }

            auto pubkeys{db.get_keys(req.path_params.at("username"))};
            json pubkeys_json(json::value_t::array);
            for(const auto& [keyid, pubkey] : pubkeys)
                pubkeys_json.push_back({{"keyid", keyid}, {"key", pubkey}});
            res.set_content(pubkeys_json.dump(), "application/json");
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    // GROUP INTERACTIONS
    Get("/groups", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }

            json groups{};
            for(const auto& [id, name] : db.get_user_groups(username))
                groups.push_back({{"id", id}, {"name", name}});
            
            res.set_content(groups.dump(), "application/json");
            res.status = 200;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Post("/groups", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }

            int groupId{db.create_group(req.body)};
            db.add_user_to_group(groupId, username);

            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Post("/groups/:groupid/add_user", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }

        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            int groupid = std::stoi(req.path_params.at("groupid"));
            if(!is_user_in_group(username, groupid)) { res.status = 401; return; }

            db.add_user_to_group(groupid, req.body);
            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Get("/groups/:groupid/messages", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }
        
        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            int groupid = std::stoi(req.path_params.at("groupid"));
            if(!is_user_in_group(username, groupid)) { res.status = 401; return; }

            auto messages{db.get_group_messages(groupid)};
            json messages_json(json::value_t::array);
            for(const auto& message : messages)
                messages_json.push_back({
                    {"from", message.from},
                    {"to", message.to},
                    {"timestamp", message.timestamp},
                    {"content", message.content},
                    {"decryption_key", message.decryption_key}
                });
            res.set_content(messages_json.dump(), "application/json");
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Post("/groups/:groupid/messages", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }
        
        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            int groupid = std::stoi(req.path_params.at("groupid"));
            if(!is_user_in_group(username, groupid)) { res.status = 401; return; }

            json data{ json::parse(req.body) };
            data = data.at(0);

            TextMessage message {
                GROUP, username, std::to_string(groupid),
                (int)std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count(),
                data.at("decryption_key"),
                data.at("content")
            };
            db.add_group_message(message);
            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Get("/groups/:groupid/pubkeys", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }
        
        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            int groupid = std::stoi(req.path_params.at("groupid"));
            if(!is_user_in_group(username, groupid)) { res.status = 401; return; }

            auto pubkeys{db.get_keys_by_groupid(groupid)};
            json pubkeys_json(json::value_t::array);
            for(const auto& [keyid, pubkey] : pubkeys)
                pubkeys_json.push_back({{"keyid", keyid}, {"key", pubkey}});
            
            res.set_content(pubkeys_json.dump(), "application/json");
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Post("/groups/:groupid/files", [&](const httplib::Request& req, httplib::Response& res, const httplib::ContentReader &content_reader) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }
        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            int groupid{std::stoi(req.path_params.at("groupid"))};
            if(!is_user_in_group(username, groupid)) { res.status = 401; return; }
            if(!req.has_header("filename")) { res.status = 400; return; }

            std::string localname{get_uuid()}, decryption_key;
            std::ofstream filestream{"data/files/"+localname};
            content_reader(
                [&](const char *data, size_t data_length) {
                    if(data_length > 1) {
                        decryption_key = std::string(data, data_length);
                        return true;
                    }
                    filestream.write(data, data_length);
                    return true;
                }
            );
            filestream.close();
            
            File file {
                GROUP, username, std::to_string(groupid),
                (int)std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch()).count(),
                decryption_key,
                req.get_header_value("filename"),
                localname
            };
            db.register_file(file);

            res.status = 201;
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    Get("/groups/:groupid/files", [&](const httplib::Request& req, httplib::Response& res) {
        if(!req.has_header("Authorization")) { res.status = 401; return; }
        std::string auth = req.get_header_value("Authorization");
        try {
            auto [username, password]{parse_auth(auth)};
            if(!auth_user(username, password)) { res.status = 401; return; }
            int groupid = std::stoi(req.path_params.at("groupid"));
            if(!is_user_in_group(username, groupid)) { res.status = 401; return; }

            auto files{db.get_files(groupid)};
            json files_json(json::value_t::array);
            for(const auto& file : files)
                files_json.push_back({
                    {"from", file.from},
                    {"to", file.to},
                    {"timestamp", file.timestamp},
                    {"filename", file.filename},
                    {"remote_filename", file.localname},
                    {"decryption_key", file.decryption_key}
                });
            res.set_content(files_json.dump(), "application/json");
        } catch(const std::runtime_error& e) {
            res.status = 400; return;
        }
    });

    // FILE INTERACTIONS
    set_mount_point("/files", "data/files");
}

void Server::run(int port) {
    listen("0.0.0.0", port);
}