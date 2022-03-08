#pragma once

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <openenclave/enclave.h>
#include <string>
#include "common/shared.h"

using namespace std;

#define SEAL_KEY_SIZE 16
#define CIPHER_BLOCK_SIZE 16
#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false
#define HASH_VALUE_SIZE_IN_BYTES 32

class ecall_dispatcher {
private:
    mbedtls_ctr_drbg_context m_ctr_drbg_contex;
    mbedtls_entropy_context m_entropy_context;

    unsigned char *m_data;
    size_t m_data_size;
    sealed_data_t *m_sealed_data;

    struct aes_context* m_aescontext;
    bool m_encrypt;
    string m_password;

    encryption_header_t* m_header;

    // initialization vector
    unsigned char m_operating_iv[IV_SIZE];

    // key for encrypting  data
    unsigned char m_encryption_key[ENCRYPTION_KEY_SIZE_IN_BYTES];


public:
    ecall_dispatcher();

    ~ecall_dispatcher();

    // two ecalls
    int seal_data(
            int seal_policy,
            unsigned char *opt_mgs,
            size_t opt_msg_len,
            unsigned char *data,
            size_t data_size,
            sealed_data_t **sealed_data,
            size_t *sealed_data_size);

    int unseal_data(
            sealed_data_t *sealed_data,
            size_t sealed_data_size,
            unsigned char **data,
            size_t *data_size);

    int initialize(
            bool encrypt,
            const char* password,
            size_t password_len,
            encryption_header_t* header);
    int encrypt_block(
            bool encrypt,
            unsigned char* input_buf,
            unsigned char* output_buf,
            size_t size);
    void close();

private:
    void init_mbedtls(void);

    void cleanup_mbedtls(void);

    int generate_iv(unsigned char *iv, unsigned int ivLen);

    oe_result_t get_seal_key_and_prep_sealed_data(
            int seal_policy,
            unsigned char *data,
            size_t data_size,
            unsigned char *opt_mgs,
            size_t opt_msg_len,
            uint8_t **seal_key,
            size_t *seal_key_size);

    oe_result_t get_seal_key_by_policy(
            int policy,
            uint8_t **key_buf,
            size_t *key_buf_size,
            uint8_t **key_info,
            size_t *key_info_size);

    oe_result_t get_seal_key_by_keyinfo(
            uint8_t *key_info,
            size_t key_info_size,
            uint8_t **key_buf,
            size_t *key_buf_size);

    int cipher_data(
            bool encrypt,
            unsigned char *input_data,
            unsigned int input_data_size,
            unsigned char *key,
            unsigned int key_size,
            unsigned char *iv,
            unsigned char *output_data);

    int sign_sealed_data(
            sealed_data_t *sealed_data,
            unsigned char *key,
            unsigned int key_size,
            uint8_t *signature);

    int generate_password_key(
            const char* password,
            unsigned char* salt,
            unsigned char* key,
            unsigned int key_size);
    int generate_encryption_key(unsigned char* key, unsigned int key_size);
    int prepare_encryption_header(encryption_header_t* header, string password);
    int parse_encryption_header(encryption_header_t* header, string password);
    int cipher_encryption_key(
            bool encrypt,
            unsigned char* input_data,
            unsigned int input_data_size,
            unsigned char* encrypt_key,
            unsigned char* salt,
            unsigned char* output_data,
            unsigned int output_data_size);
    int Sha256(
            const uint8_t* data,
            size_t data_size,
            uint8_t sha256[HASH_VALUE_SIZE_IN_BYTES]);
    int process_encryption_header(encryption_header_t* header);

    void dump_data(const char *name, unsigned char *data, size_t data_size);
};
