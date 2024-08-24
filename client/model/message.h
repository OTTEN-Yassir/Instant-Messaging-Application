#ifndef MODEL_MESSAGE_H
#define MODEL_MESSAGE_H

#include <string>
#include <vector>

namespace model {

/**
 * @brief Enumeration for the type of message.
 */
enum MessageType {
    TEXT, ///< Text message
    FILE  ///< File message
};

/**
 * @brief Structure representing a message.
 */
struct Message {
    MessageType type;      ///< Type of the message (TEXT or FILE)
    std::string sender;    ///< Username of the sender
    std::string receiver;  ///< Username of the receiver
    unsigned timestamp;    ///< Timestamp of when the message was sent
    std::string decryption_key; ///< Key used to decrypt the message
    std::string content;   ///< Content of the message (text or file data)
    std::string remote_filename; ///< Filename of the remote file if the message is a file
};

}; // namespace model

#endif // MODEL_MESSAGE_H
