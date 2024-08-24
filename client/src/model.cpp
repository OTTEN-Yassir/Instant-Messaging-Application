#include "../model/core.h"
#include "../model/message.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace model {

Core::Core(const std::string& host, int port) : logged_in{}, http_client{host, port}, currentDestination{DestType::NONE} {
    http_client.set_keep_alive(true);

    std::thread t{[this] {
        while(true) {
            if(!logged_in) { continue; }
            std::this_thread::sleep_for(std::chrono::seconds(1));
            fetchMessages();
            notifyObservers("CYCLIC_UPDATE");
        }
    }};
    t.detach();
}

void Core::registerUser(const std::string& username, const std::string& password) {
    http_client.set_basic_auth(username, password);
    if(http_client.Post("/register")->status != 201) {
        http_client.set_basic_auth("", "");
        throw std::runtime_error{"Failed to register user"};
    }

    login(username, password);
}

void Core::login(const std::string& username, const std::string& password) {
    http_client.set_basic_auth(username, password);
    if(http_client.Get("/verify_creds")->status != 200) {
        http_client.set_basic_auth("", "");
        throw std::runtime_error{"Failed to login"};
    }

    bool has_key{};
    for(const auto& keyid : fetchKeys(username))
        if(crypto.has_key(keyid, true)) {
            has_key = true;
            break;
        }
    
    if(!has_key)
        generateAndSendKey(username);
    logged_in = true;
    this->username = username;
}

void Core::generateAndSendKey(const std::string& user) {
    const std::string keyid{crypto.generate_keypair(user)};
    std::string pubkey{crypto.get_key(keyid)};
    if(http_client.Post("/add_key", {{"keyid", keyid}}, pubkey, "text/plain")->status != 201)
        throw std::runtime_error{"Failed to register key"};
}

void Core::fetchMessages() {
    if(currentDestination.type == DestType::NONE)
        return;
    
    // Fetch messages
    auto res{http_client.Get((currentDestination.type == DIRECT ? "/users/" : "/groups/") + currentDestination.id + "/messages")};
    if(res->status != 200)
        throw std::runtime_error{"Failed to fetch messages"};
    
    messages_buffer.clear();
    json messages{json::parse(res->body)};

    if(!messages.empty())
        messages = messages.at(0);

    for(const auto& message : messages) {
        std::string decrypted_msg{"Failed to decrypt message"};

        Message msg{
            TEXT,
            message.at("from"), message.at("to"),
            message.at("timestamp"),
            message.at("decryption_key"),
            message.at("content")
        };
        try {
            decrypted_msg = crypto.decrypt(msg);
        } catch (const std::runtime_error& e) {
            std::cout << e.what() << std::endl;
        }
        msg.content = decrypted_msg;

        messages_buffer.push_back(msg);
    }

    // Fetch files
    res = http_client.Get((currentDestination.type == DIRECT ? "/users/" : "/groups/") + currentDestination.id + "/files");
    if(res->status != 200)
        throw std::runtime_error{"Failed to fetch files"};
    
    json files{json::parse(res->body)};
    if(!files.empty())
        files = files.at(0);
    
    for(const auto& file : files) {
        Message msg{
            FILE,
            file.at("from"), file.at("to"),
            file.at("timestamp"),
            file.at("decryption_key"),
            file.at("filename"),
            file.at("remote_filename")
        };
        messages_buffer.push_back(msg);
    }
    std::sort(std::begin(messages_buffer), std::end(messages_buffer), [](const Message& a, const Message& b) {
        return a.timestamp < b.timestamp;
    });
}

std::vector<std::string> Core::fetchKeys(const std::string& username) {
    auto res{http_client.Get("/users/"+username+"/pubkeys")};
    if(res->status != 200)
        throw std::runtime_error{"Failed to fetch public keys"};

    json keys{json::parse(res->body)};
    if(!keys.empty())
        keys = keys.at(0);
    
    std::vector<std::string> keyids;
    for(const auto& key : keys) {
        crypto.import_keys(key.at("key"));
        keyids.push_back(key.at("keyid"));
    }
    
    return keyids;
}

std::vector<std::string> Core::fetchKeysByGroupid(int groupid) {
    auto res{http_client.Get("/groups/"+std::to_string(groupid)+"/pubkeys")};
    if(res->status != 200)
        throw std::runtime_error{"Failed to fetch public keys"};

    json keys{json::parse(res->body)};
    if(!keys.empty())
        keys = keys.at(0);
    
    std::vector<std::string> keyids;
    for(const auto& key : keys) {
        crypto.import_keys(key.at("key"));
        keyids.push_back(key.at("keyid"));
    }
    
    return keyids;
}

const std::vector<Message>& Core::getMessages() const {
    return messages_buffer;
}

void Core::setDestination(const Destination& dest) {
    currentDestination = dest;

    fetchMessages();
    notifyObservers("MESSAGES");
    notifyObservers("CONTACTS");
}

void Core::sendMessage(const std::string& content) {
    if(currentDestination.type == DestType::NONE)
        return;
    
    std::vector<std::string> keyids;
    if(currentDestination.type == DestType::DIRECT) {
        auto tmp{fetchKeys(currentDestination.id)};
        keyids = fetchKeys(username);
        keyids.insert(std::end(keyids), std::begin(tmp), std::end(tmp));
    }
    else
        keyids = fetchKeysByGroupid(std::stoi(currentDestination.id));
    
    Message encrypted{crypto.encrypt(content, keyids)}; // Encrypt message
    json msg{
        {"to", currentDestination.id},
        {"content", encrypted.content},
        {"decryption_key", encrypted.decryption_key}
    };
    
    if(http_client.Post((currentDestination.type == DIRECT ? "/users/" : "/groups/") + currentDestination.id + "/messages", msg.dump(), "application/json")->status != 201)
        throw std::runtime_error{"Failed to send message"};
}

void Core::addContact(const std::string& user) {
    if(http_client.Put("/contacts", user, "text/plain")->status != 201)
        throw std::runtime_error{"Failed to add contact"};

    notifyObservers("CONTACTS");
}

std::vector<std::string> Core::getContacts() {
    auto res{http_client.Get("/contacts")};
    if(res->status != 200)
        throw std::runtime_error{"Failed to fetch contacts"};

    json contacts{json::parse("{\"contacts\" : "+res->body+"}")};

    std::vector<std::string> result;
    for(const auto& contact : contacts.at(0).at("contacts"))
        result.push_back(contact);
    
    return result;
}

std::vector<std::pair<int, std::string>> Core::getGroups() {
    auto res{http_client.Get("/groups")};
    if(res->status != 200)
        throw std::runtime_error{"Failed to fetch groups"};

    json groups{json::parse(res->body)};
    if(!groups.empty())
        groups = groups.at(0);

    std::vector<std::pair<int, std::string>> result;
    for(const auto& group : groups)
        result.push_back({group.at("id"), group.at("name")});
    
    return result;
}

const Destination& Core::getCurrentDestination() const {
    return currentDestination;
}

void Core::sendFile(const std::string& file) {
    if(currentDestination.type == DestType::NONE)
        return;

    std::vector<std::string> keyids;
    if(currentDestination.type == DestType::DIRECT) {
        auto tmp{fetchKeys(currentDestination.id)};
        keyids = fetchKeys(username);
        keyids.insert(std::end(keyids), std::begin(tmp), std::end(tmp));
    }
    else
        keyids = fetchKeysByGroupid(std::stoi(currentDestination.id));
    
    auto encrypted_file{crypto.encrypt_file(file, keyids)};
    auto path{(currentDestination.type == DIRECT ? "/users/" : "/groups/") + currentDestination.id + "/files"};
    httplib::Headers headers{{"filename", file.substr(file.find_last_of('/')+1)}};

    auto res{http_client.Post(
        path, headers,
        [&, encrypted_file](size_t offset, httplib::DataSink& sink) {
            sink.write(encrypted_file.decryption_key.c_str(), encrypted_file.decryption_key.size());
            std::ifstream fileStream{encrypted_file.content};
            fileStream.seekg(offset);
            char buffer;
            while(fileStream.get(buffer))
                sink.write(&buffer, 1);

            sink.done();
            fileStream.close();
            return true;
        },
        "text/plain"
    )};
}

const std::string& Core::getUsername() const {
    return username;
}

void Core::createGroup(const std::string& name) {
    if(http_client.Post("/groups", name, "text/plain")->status != 201)
        throw std::runtime_error{"Failed to create group"};
}

void Core::addUserToGroup(int groupid, const std::string& user) {
    if(http_client.Post("/groups/"+std::to_string(groupid)+"/add_user", user, "text/plain")->status != 201)
        throw std::runtime_error{"Failed to add user to group"};
}

void Core::downloadFile(const std::string& remote_filename, const std::string& local_filename, const std::string& decryption_key) {
    std::ofstream downloaded_file{"tmp/"+remote_filename};
    auto res{http_client.Get("/files/"+remote_filename, [&](const char *data, size_t data_length) {
        downloaded_file.write(data, data_length);
        return true;
    })};
    if(res->status != 200)
        throw std::runtime_error{"Failed to download file"};
    downloaded_file.close();

    crypto.decrypt_file("tmp/"+remote_filename, "downloads/"+local_filename, decryption_key);
}

}; // namespace model