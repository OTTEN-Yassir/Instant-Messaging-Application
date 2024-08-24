#ifndef MODEL_CORE_H
#define MODEL_CORE_H

#include "crypto.h"
#include "../utils/subject.h"
#include <httplib.h>
#include "../model/message.h"

namespace model {
/**
 * @brief Enumeration to represent the type of destination.
 */
enum DestType {
    DIRECT, ///< Direct message
    GROUP, ///< Group message
    NONE ///< No destination
};

/**
 * @brief Structure to represent a destination.
 */
struct Destination {
    DestType type;    ///< Type of the destination (DIRECT or GROUP).
    std::string id;   ///< Identifier of the destination.
};

/**
 * @brief Core class to handle the main functionalities of the messaging application.
 */
class Core : public nvs::Subject {
    Crypto crypto;
    httplib::Client http_client;
    Destination currentDestination;
    bool logged_in;
    std::string username;
    std::vector<Message> messages_buffer;
public:
    /**
     * @brief Constructs a Core object with the given server host and port.
     * @param host The server host.
     * @param port The server port.
     */
    Core(const std::string& host, int port);

    /**
     * @brief Registers a new user with the specified username and password.
     * @param username The username of the new user.
     * @param password The password of the new user.
     */
    void registerUser(const std::string& username, const std::string& password);

    /**
     * @brief Logs in a user with the specified username and password.
     * @param username The username of the user.
     * @param password The password of the user.
     */
    void login(const std::string& username, const std::string& password);

    /**
     * @brief Generates and sends an encryption key to the specified user.
     * @param user The username of the recipient user.
     */
    void generateAndSendKey(const std::string& user);

    /**
     * @brief Fetches messages from the server.
     */
    void fetchMessages();
    /**
     * @brief Fetches public keys of a user.
     * @param username Username
     * @return Vector of public keys
     */
    std::vector<std::string> fetchKeys(const std::string& username);

    /**
     * @brief Fetches public keys of a group by its identifier.
     * @param groupid Group identifier
     * @return Vector of public keys
     */
    std::vector<std::string> fetchKeysByGroupid(int groupid);

    /**
     * @brief Sends a message.
     * @param content Message content
     */
    void sendMessage(const std::string& content);

    /**
     * @brief Encrypts and sends a file.
     * @param file File path
     */
    void sendFile(const std::string& filePath);

    /**
     * @brief Adds a contact.
     * @param user Username of the contact
     */
    void addContact(const std::string& user);

    /**
     * @brief Creates a group.
     * @param name Group name
     */
    void createGroup(const std::string& name);

    /**
     * @brief Adds a user to a group.
     * @param groupid Group identifier
     * @param user Username
     */
    void addUserToGroup(int groupid, const std::string& user);
    /**
     * @brief Downloads a file from a remote location and decrypts it.
     * @param remote_filename The name of the remote file
     * @param local_filename The name of the local file to save
     * @param decryption_key The key used to decrypt the file
     */
    void downloadFile(const std::string& remote_filename, const std::string& local_filename, const std::string& decryption_key);

    // Setters
    /**
     * @brief Sets the current destination.
     * @param dest Destination
     */
    void setDestination(const Destination& dest);

    // Getters
    /**
     * @brief Gets the messages.
     * @return Vector of messages
     */
    const std::vector<Message>& getMessages() const;

    /**
     * @brief Gets the contacts.
     * @return Vector of usernames of contacts
     */
    std::vector<std::string> getContacts();

    /**
     * @brief Gets the groups.
     * @return Vector of pairs (group identifier, group name)
     */
    std::vector<std::pair<int, std::string>> getGroups();

    /**
     * @brief Gets the current destination.
     * @return Current destination
     */
    const Destination& getCurrentDestination() const;

    /**
     * @brief Gets the username.
     * @return Username
     */
    const std::string& getUsername() const;
};

};

#endif // MODEL_CORE_H