#include "../database.h"
#include "../message.h"
#include <stdexcept>
#include <iostream>

// Database
Database::Database(const std::string& data_dir) {
    if(sqlite3_open((data_dir + "/database.db").c_str(), &db) != SQLITE_OK) {
        sqlite3_close(db);
        throw std::runtime_error("Failed to open database");
    }
}

Database::~Database() {
    sqlite3_close(db);
}

void Database::create_user(const std::string& username, const std::string& password) {
    std::string query{"INSERT INTO users (`username`, `password`) VALUES ('" + username + "', '" + password + "');"};
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to create user");
}

void Database::add_key(const std::string& username, const std::string& keyid, const std::string& key) {
    std::string query{"INSERT INTO public_keys (`id`, `owner`, `key`) VALUES ('" + keyid + "','" + username + "', '" + key + "');"};
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to add key");
}

void Database::add_direct_message(const TextMessage& message) {
    std::string query{"INSERT INTO messages (`from`, `timestamp`, `content`, `decryption_key`) VALUES ('" + message.from + "', '" + std::to_string(message.timestamp) + "', '" + message.content + "', '" + message.decryption_key + "');"};
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to add message");

    query = "INSERT INTO direct_messages (`id`, `to`) VALUES ('" + std::to_string(sqlite3_last_insert_rowid(db)) + "','" + message.to + "');";
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to add message");
}

void Database::add_group_message(const TextMessage& message) {
    std::string query{"INSERT INTO messages (`from`, `timestamp`, `content`, `decryption_key`) VALUES ('" + message.from + "', '" + std::to_string(message.timestamp) + "', '" + message.content + "', '" + message.decryption_key + "');"};
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to add message");

    query = "INSERT INTO `group_messages` (`id`, `to`) VALUES ('" + std::to_string(sqlite3_last_insert_rowid(db)) + "','" + message.to + "');";
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to add message");
}

void Database::add_contact(const std::string& username, const std::string& contact) {
    std::string query{"INSERT INTO contacts (`user`, `contact`) VALUES ('" + username + "','" + contact + "');"};
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to add contact");
}

int Database::create_group(const std::string& groupname) {
    std::string query{"INSERT INTO groups (`name`) VALUES ('" + groupname + "');"};
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to create group");
    
    return sqlite3_last_insert_rowid(db);
}

void Database::add_user_to_group(int groupid, const std::string& username) {
    std::string query{"INSERT INTO group_users (`group`, `user`) VALUES ('" + std::to_string(groupid) + "','" + username + "');"};
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to add user to group");
}

std::vector<std::string> Database::get_contacts(const std::string& username) {
    std::string query{"SELECT contact FROM contacts WHERE `user` = '" + username + "';"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");

    std::vector<std::string> contacts;
    while(sqlite3_step(stmt) == SQLITE_ROW)
        contacts.push_back(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)));
    sqlite3_finalize(stmt);
    return contacts;
}

std::string Database::get_user_hash(const std::string& username) {
    std::string query{"SELECT password FROM users WHERE `username` = '" + username + "';"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");

    if(sqlite3_step(stmt) != SQLITE_ROW)
        throw std::runtime_error("sqlite3: User not found");

    std::string hash{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))};
    sqlite3_finalize(stmt);
    return hash;
}

std::vector<std::pair<std::string, std::string>> Database::get_keys(const std::string& username) {
    std::string query{"SELECT `id`, `key` FROM public_keys WHERE `owner` = '" + username + "';"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");

    std::vector<std::pair<std::string, std::string>> keys;
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        keys.push_back({
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))
        });
    }
    sqlite3_finalize(stmt);
    return keys;
}

std::vector<TextMessage> Database::get_direct_messages(const std::string& from, const std::string& to) {
    std::string query{"SELECT `messages`.`from`, `direct_messages`.`to`, `messages`.`timestamp`, `messages`.`decryption_key`, `messages`.`content` FROM `messages` JOIN `direct_messages` ON `messages`.`id` = `direct_messages`.`id` WHERE (`messages`.`from` = '" + from + "' AND `direct_messages`.`to` = '" + to + "') OR (`messages`.`from` = '" + to + "' AND `direct_messages`.`to` = '" + from + "');"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");
    
    std::vector<TextMessage> messages;
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        TextMessage message{
            DIRECT,
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))},
            sqlite3_column_int(stmt, 2),
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))}
        };
        messages.push_back(message);
    }
    sqlite3_finalize(stmt);
    return messages;
}

std::vector<TextMessage> Database::get_group_messages(int groupid) {
    std::string query{"SELECT `messages`.`from`, `group_messages`.`to`, `messages`.`timestamp`, `messages`.`decryption_key`, `messages`.`content` FROM `messages` JOIN `group_messages` ON `messages`.`id` = `group_messages`.`id` WHERE `group_messages`.`to` = '" + std::to_string(groupid) + "';"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");
    
    std::vector<TextMessage> messages;
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        TextMessage message{
            GROUP,
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))},
            sqlite3_column_int(stmt, 2),
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))}
        };
        messages.push_back(message);
    }
    sqlite3_finalize(stmt);
    return messages;
}

std::vector<Group> Database::get_user_groups(const std::string& username) {
    std::string query{"SELECT DISTINCT `group_users`.`group`, `groups`.`name` FROM `group_users` JOIN `groups` ON `group_users`.`group` = `groups`.`id` WHERE `group_users`.`user` = '" + username + "';"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");

    std::vector<Group> groups;
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        groups.push_back({
            sqlite3_column_int(stmt, 0),
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))}
        });
    }
    sqlite3_finalize(stmt);
    return groups;
}

std::vector<std::pair<std::string, std::string>> Database::get_keys_by_groupid(int groupid) {
    std::string query{"SELECT DISTINCT `public_keys`.`id`, `public_keys`.`key` FROM `public_keys` JOIN `group_users` ON `public_keys`.`owner` = `group_users`.`user` WHERE `group_users`.`group` = '" + std::to_string(groupid) + "';"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");

    std::vector<std::pair<std::string, std::string>> keys;
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        keys.push_back({
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0)),
            reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))
        });
    }
    sqlite3_finalize(stmt);
    return keys;
}

void Database::register_file(const File& file) {
    std::string query{"INSERT INTO files (`localname`, `filename`, `from`, `timestamp`, `decryption_key`) VALUES ('" + file.localname + "', '" + file.filename + "', '" + file.from + "', '" + std::to_string(file.timestamp) + "', '" + file.decryption_key + "');"};
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to register file");

    std::string table{file.destinationType == DIRECT ? "direct_files" : "group_files"};
    query = "INSERT INTO " + table + " (`id`, `to`) VALUES ('" + std::to_string(sqlite3_last_insert_rowid(db)) + "', '" + file.to + "');";
    if(sqlite3_exec(db, query.c_str(), nullptr, nullptr, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to register file");
}

std::vector<File> Database::get_files(int groupid) {
    std::string query{"SELECT `files`.`from`, `group_files`.`to`, `files`.`timestamp`, `files`.`decryption_key`, `files`.`filename`, `files`.`localname` FROM `files` JOIN `group_files` ON `files`.`id` = `group_files`.`id` WHERE `group_files`.`to` = '" + std::to_string(groupid) + "';"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");

    std::vector<File> files;
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        File file{
            GROUP,
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))},
            sqlite3_column_int(stmt, 2),
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5))}
        };
        files.push_back(file);
    }
    sqlite3_finalize(stmt);
    return files;
}

std::vector<File> Database::get_files(const std::string& from, const std::string& to) {
    std::string query{"SELECT `files`.`from`, `direct_files`.`to`, `files`.`timestamp`, `files`.`decryption_key`, `files`.`filename`, `files`.`localname` FROM `files` JOIN `direct_files` ON `files`.`id` = `direct_files`.`id` WHERE (`files`.`from` = '" + from + "' AND `direct_files`.`to` = '" + to + "') OR (`files`.`from` = '" + to + "' AND `direct_files`.`to` = '" + from + "');"};
    sqlite3_stmt* stmt;
    if(sqlite3_prepare_v2(db, query.c_str(), query.size(), &stmt, nullptr) != SQLITE_OK)
        throw std::runtime_error("sqlite3: Failed to prepare statement");

    std::vector<File> files;
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        File file{
            DIRECT,
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1))},
            sqlite3_column_int(stmt, 2),
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4))},
            std::string{reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5))}
        };
        files.push_back(file);
    }
    sqlite3_finalize(stmt);
    return files;
}