// Header guard
#ifndef SERVER_H
#define SERVER_H

#include <httplib.h>
#include "database.h"

/**
 * @brief Class representing the server.
 */
class Server : public httplib::Server {
    Database db;

    static std::string hash(const std::string& content);
    static std::pair<std::string, std::string> parse_auth(const std::string& auth);
    bool auth_user(const std::string& username, const std::string& password);
    bool is_user_in_group(const std::string& username, int groupid);

public:
    /**
     * @brief Constructs the Server object.
     * @param data_dir The directory for storing data
     */
    Server(const std::string& data_dir);

    /**
     * @brief Runs the server on the specified port.
     * @param port The port to run the server on
     */
    void run(int port);
};

#endif // SERVER_H
