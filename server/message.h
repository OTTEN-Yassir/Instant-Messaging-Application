#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>

/**
 * @brief Enumeration for the type of destination.
 */
enum DestType {
    DIRECT, ///< Direct message
    GROUP   ///< Group message
};

/**
 * @brief Structure representing a generic message.
 */
struct Message {
    DestType destinationType;
    std::string from;
    std::string to;
    int timestamp;
    std::string decryption_key;
};

/**
 * @brief Structure representing a file message.
 */
struct File : public Message {
    std::string filename;  ///< Name of the file
    std::string localname; ///< Local name of the file
};

/**
 * @brief Structure representing a text message.
 */
struct TextMessage : public Message {
    std::string content; ///< Content of the text message
};

#endif // MESSAGE_H
