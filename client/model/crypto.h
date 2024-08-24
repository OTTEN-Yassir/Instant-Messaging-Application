#ifndef MODEL_CRYPTO_H
#define MODEL_CRYPTO_H

#include <rnp/rnp.h>
#include <vector>
#include <string>

namespace model {

/**
 * @brief Structure representing a message.
 */
struct Message;

/**
 * @brief Class handling cryptographic operations.
 */
class Crypto {
    rnp_ffi_t ffi;
    std::vector<std::string> pubkey_ids;
public:
    /**
     * @brief Constructs the Crypto object.
     */
    Crypto();

    /**
     * @brief Destroys the Crypto object.
     */
    ~Crypto();

    /**
     * @brief Generates a key pair for a user.
     * @param user Username
     * @return Key pair as a string
     */
    std::string generate_keypair(const std::string& user);

    /**
     * @brief Loads a keyring from a specified path.
     * @param path Path to the keyring file
     */
    void load_keyring(const std::string& path);

    /**
     * @brief Saves the keyring to a specified path.
     * @param path Path to save the keyring
     */
    void save_keyring(const std::string& path);

    /**
     * @brief Imports keys from a string.
     * @param keys Keys to import
     * @param secret Whether the keys are secret keys (default: false)
     */
    void import_keys(const std::string& keys, bool secret = false);

    /**
     * @brief Retrieves a key by its ID.
     * @param keyid Key ID
     * @param secret Whether to retrieve the secret key (default: false)
     * @return Key as a string
     */
    std::string get_key(const std::string& keyid, bool secret = false);

    /**
     * @brief Encrypts a message for the given public keys.
     * @param message Message to encrypt
     * @param pubkeys Vector of public key IDs
     * @return Encrypted message
     */
    Message encrypt(const std::string& message, const std::vector<std::string>& pubkeys);

    /**
     * @brief Decrypts a message.
     * @param message Message to decrypt
     * @return Decrypted message as a string
     */
    std::string decrypt(const Message& message);

    /**
     * @brief Encrypts a file for the given public keys.
     * @param path Path to the file to encrypt
     * @param pubkeys Vector of public key IDs
     * @return Encrypted file information
     */
    Message encrypt_file(const std::string& path, const std::vector<std::string> & pubkeys);

    /**
     * @brief Decrypts a file.
     * @param path Path to the file to decrypt
     * @param outpath Path to save the decrypted file
     * @param decryption_key Encrypted decryption key
     */
    void decrypt_file(const std::string& path, const std::string& outpath, const std::string& decryption_key);

    /**
     * @brief Checks if a key exists by its ID.
     * @param keyid Key ID
     * @param secret Whether to check for a secret key (default: false)
     * @return True if the key exists, false otherwise
     */
    bool has_key(const std::string& keyid, bool secret = false);
};

};

#endif // MODEL_CRYPTO_H
