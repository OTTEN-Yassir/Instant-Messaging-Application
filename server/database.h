#ifndef SERVER_DATABASE_H
#define SERVER_DATABASE_H

#include <sqlite3.h>
#include <string>
#include <vector>

struct File;
struct TextMessage;

using Group = std::pair<int, std::string>; 

/**
 * @brief Class handling database operations.
 */
class Database {
    sqlite3 *db; ///< SQLite database connection
public:
    /**
     * @brief Constructs the Database object and initializes the database connection.
     * @param data_dir The directory for storing database files
     */
    Database(const std::string& data_dir);

    /**
     * @brief Destroys the Database object and closes the database connection.
     */
    ~Database();

    /**
     * @brief Creates a new user in the database.
     * @param username The username
     * @param password The password
     */
    void create_user(const std::string& username, const std::string& password);

    /**
     * @brief Adds a key for a user.
     * @param username The username
     * @param keyid The key ID
     * @param key The key
     */
    void add_key(const std::string& username, const std::string& keyid, const std::string& key);

    /**
    * @brief Adds a direct message to the database.
    * @param message The message to add.
    */
    void add_direct_message(const TextMessage& message);

    /**
    * @brief Adds a group message to the database.
    * @param message The message to add.
    */
    void add_group_message(const TextMessage& message);

    /**
    * @brief Adds a contact for a user.
    * @param username The username of the user.
    * @param contact The username of the contact to add.
    */
    void add_contact(const std::string& username, const std::string& contact);


    /**
     * @brief Creates a new group in the database.
     * @param groupname The name of the group
     * @return The ID of the created group
     */
    int create_group(const std::string& groupname);

    /**
     * @brief Adds a user to a group.
     * @param groupid The group ID
     * @param username The username
     */
    void add_user_to_group(int groupid, const std::string& username);

    /**
    * @brief Registers a file in the database.
    * @param file The file to register.
    */
    void register_file(const File& file);
    

    /**
     * @brief Gets the contacts of a user.
     * @param username The username
     * @return A vector of contact usernames
     */
    std::vector<std::string> get_contacts(const std::string& username);

    /**
     * @brief Gets the hash of a user.
     * @param username The username
     * @return The user's hash
     */
    std::string get_user_hash(const std::string& username);

    /**
     * @brief Gets the keys of a user.
     * @param username The username
     * @return A vector of pairs containing key IDs and keys
     */
    std::vector<std::pair<std::string, std::string>> get_keys(const std::string& username);

    /**
     * @brief Gets the keys by group ID.
     * @param groupid The group ID
     * @return A vector of pairs containing key IDs and keys
     */
    std::vector<std::pair<std::string, std::string>> get_keys_by_groupid(int groupid);
    /**
     * @brief Retrieves direct messages between two users.
    * @param from The sender's username.
    * @param to The receiver's username.
     * @return A vector of direct messages.
    */
    std::vector<TextMessage> get_direct_messages(const std::string& from, const std::string& to);

    /**
    * @brief Retrieves group messages for a specified group.
    * @param groupid The ID of the group.
    * @return A vector of group messages.
    */
    std::vector<TextMessage> get_group_messages(int groupid);

    /**
    * @brief Retrieves groups that a user is a member of.
    * @param username The username of the user.
    * @return A vector of groups.
    */
    std::vector<Group> get_user_groups(const std::string& username);

    /**
    * @brief Retrieves files uploaded to a specified group.
    * @param groupid The ID of the group.
    * @return A vector of files.
    */
    std::vector<File> get_files(int groupid);

    /**
    * @brief Retrieves files exchanged between two users.
    * @param from The sender's username.
    * @param to The receiver's username.
    * @return A vector of files.
    */
    std::vector<File> get_files(const std::string& from, const std::string& to);

};

#endif //SERVER_DATABASE_H
