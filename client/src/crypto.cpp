#include "../model/crypto.h"
#include "../model/message.h"
#include <stdexcept>
#include <iostream>

namespace model {
    
Crypto::Crypto() {
    if(rnp_ffi_create(&ffi, "GPG", "GPG") != 0)
        throw std::runtime_error{"Failed to initialize ffi object"};
    try {
        load_keyring("./keyring.gpg");
    } catch (const std::runtime_error& e) {
        std::cout << e.what() << std::endl;
    }
}

Crypto::~Crypto() {
    save_keyring("./keyring.gpg");
    rnp_ffi_destroy(ffi);
}

std::string Crypto::generate_keypair(const std::string& user) {
    rnp_key_handle_t key;
    if (rnp_generate_key_25519(ffi, user.c_str(), NULL, &key) != 0)
        throw std::runtime_error{"Failed to generate eddsa key"};

    char* keyid;
    rnp_key_get_keyid(key, &keyid);
    return std::string{keyid};
}

void Crypto::load_keyring(const std::string& path) {
    rnp_input_t keyfile{NULL};
    if(rnp_input_from_path(&keyfile, path.c_str()) != 0)
        throw std::runtime_error{"Failed to open key file"};

    if(rnp_load_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_SECRET_KEYS | RNP_LOAD_SAVE_PUBLIC_KEYS) != 0)
        throw std::runtime_error{"Failed to load keys from file"};
};

void Crypto::save_keyring(const std::string& path) {
    rnp_output_t keyfile{NULL};
    if(rnp_output_to_path(&keyfile, path.c_str()) != 0)
        throw std::runtime_error{"Failed to create/open key file"};

    if(rnp_save_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS | RNP_LOAD_SAVE_SECRET_KEYS) != 0)
        throw std::runtime_error{"Failed to save keys to file"};
}

void Crypto::import_keys(const std::string& keys, bool secret) {
    rnp_input_t inputBuffer;
    if(rnp_input_from_memory(&inputBuffer, (const uint8_t*)keys.c_str(), keys.size(), false) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    char *buffer;
    if(rnp_import_keys(ffi, inputBuffer, (secret ? RNP_LOAD_SAVE_SECRET_KEYS : RNP_LOAD_SAVE_PUBLIC_KEYS), &buffer) != 0)
        throw std::runtime_error{"Failed to import keys"};
}

std::string Crypto::get_key(const std::string& keyid, bool secret) {
    rnp_key_handle_t key;
    if(rnp_locate_key(ffi, "keyid", keyid.c_str(), &key) != 0)
        throw std::runtime_error{"Could not locate key " + keyid};

    rnp_output_t outputBuffer;
    if(rnp_output_to_memory(&outputBuffer, 0) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    if(rnp_key_export(key, outputBuffer, RNP_KEY_EXPORT_ARMORED | (secret ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC) | RNP_KEY_EXPORT_SUBKEYS) != 0)
        throw std::runtime_error{"Failed to export key"};

    char* buffer;
    size_t len;
    rnp_output_memory_get_buf(outputBuffer, (uint8_t**)&buffer, &len, false);
    
    std::string ret{buffer}; ret.resize(len);
    return ret;
}

Message Crypto::encrypt(const std::string& message, const std::vector<std::string>& keyids) {
    Message ret;
    ret.type = TEXT;
    
    // Generate temporary keypair
    std::string keyid{generate_keypair("temp")};
    
    // Input/output buffers
    rnp_input_t inputBuffer;
    if(rnp_input_from_memory(&inputBuffer, (const uint8_t*)message.c_str(), message.size(), false) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    rnp_output_t outputBuffer;
    if(rnp_output_to_memory(&outputBuffer, 0) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    // Encrypt operation
    rnp_op_encrypt_t encryptOperation;
    if(rnp_op_encrypt_create(&encryptOperation, ffi, inputBuffer, outputBuffer) != 0)
        throw std::runtime_error{"Failed to create encrypt operation"};

    // Encrypt operation parameters
    rnp_op_encrypt_set_armor(encryptOperation, true);
    rnp_op_encrypt_set_compression(encryptOperation, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encryptOperation, RNP_ALGNAME_AES_256);

    // Encrypt message using temporary key
    rnp_key_handle_t key;
    if(rnp_locate_key(ffi, "keyid", keyid.c_str(), &key) != 0)
        throw std::runtime_error{"Could not locate key " + std::string{keyid}};

    rnp_op_encrypt_add_recipient(encryptOperation, key);
    rnp_key_handle_destroy(key);
    key = NULL;
    

    // Execute encrypt operation
    if(rnp_op_encrypt_execute(encryptOperation) != 0)
        throw std::runtime_error{"Failed to execute encrypt operation"};

    char* buffer;
    size_t len;
    rnp_output_memory_get_buf(outputBuffer, (uint8_t**)&buffer, &len, false);
    ret.content = std::string{buffer};
    ret.content.resize(len);
    
    // Encrypt temporary key
    std::string decryption_key{get_key(keyid, true)};
    rnp_input_t keyBuffer;
    if(rnp_input_from_memory(&keyBuffer, (const uint8_t*)decryption_key.c_str(), decryption_key.size(), false) != 0)
        throw std::runtime_error{"Failed to create buffer"};
    
    rnp_output_t keyOutputBuffer;
    if(rnp_output_to_memory(&keyOutputBuffer, 0) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    rnp_op_encrypt_t keyEncryptOperation;
    if(rnp_op_encrypt_create(&keyEncryptOperation, ffi, keyBuffer, keyOutputBuffer) != 0)
        throw std::runtime_error{"Failed to create encrypt operation"};

    rnp_op_encrypt_set_armor(keyEncryptOperation, true);
    rnp_op_encrypt_set_compression(keyEncryptOperation, "ZIP", 6);
    rnp_op_encrypt_set_cipher(keyEncryptOperation, RNP_ALGNAME_AES_256);

    for(const std::string& userKeyid : keyids) {
        rnp_key_handle_t key;
        if(rnp_locate_key(ffi, "keyid", userKeyid.c_str(), &key) != 0)
            throw std::runtime_error{"Could not locate key " + std::string{userKeyid}};

        rnp_op_encrypt_add_recipient(keyEncryptOperation, key);
        rnp_key_handle_destroy(key);
        key = NULL;
    }

    if(rnp_op_encrypt_execute(keyEncryptOperation) != 0)
        throw std::runtime_error{"Failed to execute encrypt operation"};

    rnp_output_memory_get_buf(keyOutputBuffer, (uint8_t**)&buffer, &len, false);
    ret.decryption_key = std::string{buffer};
    ret.decryption_key.resize(len);

    return ret;
};

std::string Crypto::decrypt(const Message& message) {
    // Decrypt decryption key
    rnp_input_t keyInputBuffer;
    if(rnp_input_from_memory(&keyInputBuffer, (const uint8_t*)message.decryption_key.c_str(), message.decryption_key.size(), false) != 0)
        throw std::runtime_error{"Failed to create buffer"};
    
    rnp_output_t keyOutputBuffer;
    if(rnp_output_to_memory(&keyOutputBuffer, 0) != 0)
        throw std::runtime_error{"Failed to create buffer"};
    
    if(rnp_decrypt(ffi, keyInputBuffer, keyOutputBuffer) != 0)
        throw std::runtime_error{"failed to decrypt key"};

    // Import decryption key
    char* buffer;
    size_t len;
    rnp_output_memory_get_buf(keyOutputBuffer, (uint8_t**)&buffer, &len, false);
    std::string key{buffer};
    key.resize(len);

    import_keys(key, true);

    // Input/output buffers
    rnp_input_t inputBuffer;
    if(rnp_input_from_memory(&inputBuffer, (const uint8_t*)message.content.c_str(), message.content.size(), false) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    rnp_output_t outputBuffer;
    if(rnp_output_to_memory(&outputBuffer, 0) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    if(rnp_decrypt(ffi, inputBuffer, outputBuffer) != 0)
        throw std::runtime_error{"failed to decrypt message"};

    rnp_output_memory_get_buf(outputBuffer, (uint8_t**)&buffer, &len, false);

    std::string result{buffer};
    result.resize(len); // Remove residual padding
    return result;
}

Message Crypto::encrypt_file(const std::string& path, const std::vector<std::string>& keyids) {
    Message ret;
    ret.type = FILE;
    
    // Generate temporary keypair
    std::string keyid{generate_keypair("temp")};
    
    // Input/output buffers
    rnp_input_t inputBuffer;
    if(rnp_input_from_path(&inputBuffer, path.c_str()) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    rnp_output_t outputBuffer;
    if(rnp_output_to_file(&outputBuffer, "./tmp/encrypted", RNP_OUTPUT_FILE_OVERWRITE) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    // Encrypt operation
    rnp_op_encrypt_t encryptOperation;
    if(rnp_op_encrypt_create(&encryptOperation, ffi, inputBuffer, outputBuffer) != 0)
        throw std::runtime_error{"Failed to create encrypt operation"};

    // Encrypt operation parameters
    rnp_op_encrypt_set_armor(encryptOperation, true);
    rnp_op_encrypt_set_compression(encryptOperation, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encryptOperation, RNP_ALGNAME_AES_256);

    // Encrypt message using temporary key
    rnp_key_handle_t key;
    if(rnp_locate_key(ffi, "keyid", keyid.c_str(), &key) != 0)
        throw std::runtime_error{"Could not locate key " + std::string{keyid}};

    rnp_op_encrypt_add_recipient(encryptOperation, key);
    rnp_key_handle_destroy(key);
    key = NULL;
    

    // Execute encrypt operation
    if(rnp_op_encrypt_execute(encryptOperation) != 0)
        throw std::runtime_error{"Failed to execute encrypt operation"};
    
    // Encrypt temporary key
    std::string decryption_key{get_key(keyid, true)};
    rnp_input_t keyBuffer;
    if(rnp_input_from_memory(&keyBuffer, (const uint8_t*)decryption_key.c_str(), decryption_key.size(), false) != 0)
        throw std::runtime_error{"Failed to create buffer"};
    
    rnp_output_t keyOutputBuffer;
    if(rnp_output_to_memory(&keyOutputBuffer, 0) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    rnp_op_encrypt_t keyEncryptOperation;
    if(rnp_op_encrypt_create(&keyEncryptOperation, ffi, keyBuffer, keyOutputBuffer) != 0)
        throw std::runtime_error{"Failed to create encrypt operation"};

    rnp_op_encrypt_set_armor(keyEncryptOperation, true);
    rnp_op_encrypt_set_compression(keyEncryptOperation, "ZIP", 6);
    rnp_op_encrypt_set_cipher(keyEncryptOperation, RNP_ALGNAME_AES_256);

    for(const std::string& userKeyid : keyids) {
        rnp_key_handle_t key;
        if(rnp_locate_key(ffi, "keyid", userKeyid.c_str(), &key) != 0)
            throw std::runtime_error{"Could not locate key " + std::string{userKeyid}};

        rnp_op_encrypt_add_recipient(keyEncryptOperation, key);
        rnp_key_handle_destroy(key);
        key = NULL;
    }

    if(rnp_op_encrypt_execute(keyEncryptOperation) != 0)
        throw std::runtime_error{"Failed to execute encrypt operation"};

    char* buffer;
    size_t len;
    rnp_output_memory_get_buf(keyOutputBuffer, (uint8_t**)&buffer, &len, false);
    ret.decryption_key = std::string{buffer};
    ret.decryption_key.resize(len);
    ret.content = "tmp/encrypted";

    return ret;
}

bool Crypto::has_key(const std::string& keyid, bool secret) {
    rnp_key_handle_t key;
    if(rnp_locate_key(ffi, "keyid", keyid.c_str(), &key) != 0)
        return false;

    bool result;
    if(secret)
        rnp_key_have_secret(key, &result);
    else
        rnp_key_have_public(key, &result);

    rnp_key_handle_destroy(key);
    return result;
}

void Crypto::decrypt_file(const std::string& path, const std::string& outpath, const std::string& decryption_key) {
    // Decrypt decryption key
    rnp_input_t keyInputBuffer;
    if(rnp_input_from_memory(&keyInputBuffer, (const uint8_t*)decryption_key.c_str(), decryption_key.size(), false) != 0)
        throw std::runtime_error{"Failed to create buffer"};
    
    rnp_output_t keyOutputBuffer;
    if(rnp_output_to_memory(&keyOutputBuffer, 0) != 0)
        throw std::runtime_error{"Failed to create buffer"};
    
    if(rnp_decrypt(ffi, keyInputBuffer, keyOutputBuffer) != 0)
        throw std::runtime_error{"failed to decrypt key"};

    // Import decryption key
    char* buffer;
    size_t len;
    rnp_output_memory_get_buf(keyOutputBuffer, (uint8_t**)&buffer, &len, false);
    std::string key{buffer};
    key.resize(len);

    import_keys(key, true);

    // Input/output buffers
    rnp_input_t inputBuffer;
    if(rnp_input_from_path(&inputBuffer, path.c_str()) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    rnp_output_t outputBuffer;
    if(rnp_output_to_file(&outputBuffer, outpath.c_str(), RNP_OUTPUT_FILE_OVERWRITE) != 0)
        throw std::runtime_error{"Failed to create buffer"};

    if(rnp_decrypt(ffi, inputBuffer, outputBuffer) != 0)
        throw std::runtime_error{"failed to decrypt message"};
}

}; // namespace model