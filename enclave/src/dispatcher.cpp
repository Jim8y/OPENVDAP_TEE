#include "dispatcher.h"

#include <stdio.h>
#include <string.h>
#include <iostream> //std::cout
#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include "common/shared.h"

#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false

ecall_dispatcher::ecall_dispatcher() {
    m_data = NULL;
    m_data_size = 0;
    m_sealed_data = NULL;
    m_encrypt = true;
    m_header = nullptr;
    init_mbedtls();
}

ecall_dispatcher::~ecall_dispatcher() {
    cleanup_mbedtls();
}

void ecall_dispatcher::init_mbedtls() {
    const char pers[] = "random data string";
    mbedtls_entropy_init(&m_entropy_context);
    mbedtls_ctr_drbg_init(&m_ctr_drbg_contex);

    // mbedtls_ctr_drbg_seed seeds and sets up the CTR_DRBG entropy source for
    // future reseeds.
    mbedtls_ctr_drbg_seed(
            &m_ctr_drbg_contex,
            mbedtls_entropy_func,
            &m_entropy_context,
            (unsigned char *) pers,
            sizeof(pers));
}

void ecall_dispatcher::cleanup_mbedtls(void) {
    mbedtls_entropy_free(&m_entropy_context);
    mbedtls_ctr_drbg_free(&m_ctr_drbg_contex);
}

int ecall_dispatcher::seal_data(
        int seal_policy,
        unsigned char *opt_mgs,
        size_t opt_msg_len,
        unsigned char *data,
        size_t data_size,
        sealed_data_t **sealed_data,
        size_t *sealed_data_size) {
    oe_result_t result = OE_OK;
    int ret = 0;
    unsigned char iv[IV_SIZE];
    sealed_data_t *temp_sealed_data = NULL;

    uint8_t *seal_key = NULL;
    size_t seal_key_size = 0;

    // get seal key and allocate sealed_data_t structure and initialize with
    // basic information
    result = get_seal_key_and_prep_sealed_data(
            seal_policy,
            data,
            data_size,
            opt_mgs,
            opt_msg_len,
            &seal_key,
            &seal_key_size);
    if (result != OE_OK) {
        std::cout << "get_seal_key_and_prep_sealed_data failed with "
                  << oe_result_str(result) << std::endl;
        goto exit;
    }

    // generate random initialization vector values
//    std::cout << "generate random initialization vector values" << std::endl;
    ret = generate_iv(m_sealed_data->iv, IV_SIZE);
    if (ret != 0) {
        std::cout << "generate_iv failed with " << ret << std::endl;
        goto exit;
    }
    memcpy(iv, m_sealed_data->iv, IV_SIZE);

    // seal data: encrypt data with the seal key
    ret = cipher_data(
            ENCRYPT_OPERATION,
            m_data,
            m_data_size,
            seal_key,
            seal_key_size,
            iv,
            m_sealed_data->encrypted_data);
    if (ret != 0) {
        std::cout << "cipher_data failed with " << ret << std::endl;
        goto exit;
    }

    // On the return from above cipher_data, the iv value was updated ,
    // initialize to the original value before using it in sign_sealed_data
    memcpy(iv, m_sealed_data->iv, IV_SIZE);

    // generate signature by signing the hash of the sealed data with the seal
    // key
    ret = sign_sealed_data(
            m_sealed_data, seal_key, seal_key_size, m_sealed_data->signature);
    if (ret != 0) {
        std::cout << "sign_sealed_data " << ret << std::endl;
        goto exit;
    }
    temp_sealed_data = (sealed_data_t *) oe_host_malloc(m_sealed_data->total_size);
    if (temp_sealed_data == NULL) {
        result = OE_OUT_OF_MEMORY;
        goto exit;
    }
    memcpy(temp_sealed_data, m_sealed_data, m_sealed_data->total_size);
    *sealed_data_size = m_sealed_data->total_size;
    *sealed_data = temp_sealed_data;
    exit:
    if (m_data) {
        free(m_data);
        m_data = NULL;
    }

    if (seal_key)
        free(seal_key);

    if (m_sealed_data) {
        free(m_sealed_data);
        m_sealed_data = NULL;
    }

    if (ret)
        result = OE_FAILURE;
    return result;
}

int ecall_dispatcher::unseal_data(
        sealed_data_t *sealed_data,
        size_t sealed_data_size,
        unsigned char **data,
        size_t *data_size) {
    oe_result_t result = OE_OK;
    unsigned char iv[IV_SIZE];
    unsigned char signature[SIGNATURE_LEN];
    uint8_t *seal_key = NULL;
    size_t seal_key_size = 0;
    uint8_t *key_info = NULL;
    size_t key_info_size = 0;

    unsigned char *data_buf = NULL;
    int ret = 0;

    key_info = sealed_data->encrypted_data + sealed_data->encrypted_data_len;
    key_info_size = sealed_data->key_info_size;

    m_sealed_data = sealed_data;
    *data_size = 0;
    *data = NULL;

    // retrieve the seal key
    result =
            get_seal_key_by_keyinfo(key_info, key_info_size, &seal_key, &seal_key_size);
    if (result != OE_OK) {
        std::cout << "unseal_data failed with " << oe_result_str(result)
                  << std::endl;
        ret = ERROR_GET_SEALKEY;
        goto exit;
    }

    // read initialization vector values
    memcpy(iv, m_sealed_data->iv, IV_SIZE);

    // validate signature by re-generating a signature from the input
    // sealed_data
    // structure then comparing it with sealed_data.signature

    // regenerate signature
    ret = sign_sealed_data(m_sealed_data, seal_key, seal_key_size, signature);
    if (ret != 0) {
        ret = ERROR_SIGN_SEALED_DATA_FAIL;
        std::cout << "sign_sealed_data failed with " << ret << std::endl;
        goto exit;
    }

    // validate signature
    if (memcmp(signature, m_sealed_data->signature, SIGNATURE_LEN) != 0) {
        std::cout << "signature mismatched";
        ret = ERROR_SIGNATURE_VERIFY_FAIL;
        goto exit;
    }
    std::cout << "signature validation passed successfully" << std::endl;

    // Unseal data: decrypt data with the seal key
    // re-initialization vector values
    memcpy(iv, m_sealed_data->iv, IV_SIZE);

    data_buf = (unsigned char *) oe_host_malloc(m_sealed_data->encrypted_data_len);
    if (data_buf == NULL) {
        ret = ERROR_OUT_OF_MEMORY;
        goto exit;
    }

    ret = cipher_data(
            DECRYPT_OPERATION,
            m_sealed_data->encrypted_data,
            m_sealed_data->encrypted_data_len,
            seal_key,
            seal_key_size,
            iv,
            data_buf);
    if (ret != 0) {
        std::cout << "cipher_data failed with " << ret << std::endl;
        ret = ERROR_CIPHER_ERROR;
        goto exit;
    }

    *data_size = m_sealed_data->original_data_size;
    *data = data_buf;

    exit:
    if (seal_key)
        free(seal_key);

    return ret;
}

oe_result_t ecall_dispatcher::get_seal_key_and_prep_sealed_data(
        int seal_policy,
        unsigned char *data,
        size_t data_size,
        unsigned char *opt_mgs,
        size_t opt_msg_len,
        uint8_t **seal_key,
        size_t *seal_key_size) {
    oe_result_t result = OE_OK;
    size_t bytes_left = 0;
    size_t total_size = 0;
    size_t original_data_size = 0;
    uint8_t *key_info;
    size_t key_info_size;
    unsigned char *padded_data = NULL;
    size_t padded_byte_count = 0;

    // retrieve the seal key
    result = get_seal_key_by_policy(
            seal_policy, seal_key, seal_key_size, &key_info, &key_info_size);
    if (result != OE_OK) {
        std::cout << "get_seal_key_by_policy failed with " << oe_result_str(result)
                  << std::endl;
        goto exit;
    }
//    std::cout << "seal_key_size " << *seal_key_size << std::endl;
//    std::cout << "key_info_size " << key_info_size << std::endl;
//    std::cout << "data_size " << data_size << std::endl;

    m_data = data;
    m_data_size = data_size;
    original_data_size = data_size;

    // cbc encryption used in this sample required CIPHER_BLOCK_SIZE alignment
    // update the data and its size if padding is needed
    bytes_left = m_data_size % CIPHER_BLOCK_SIZE;

    // PKCS5 padding
    // if the original data size is an integer multiple of blocks
    // pad n extra block of bytes with value N is added
    if (bytes_left == 0)
        padded_byte_count = CIPHER_BLOCK_SIZE;
    else
        padded_byte_count = CIPHER_BLOCK_SIZE - bytes_left;

    padded_data = (unsigned char *) malloc(m_data_size + padded_byte_count);
    if (padded_data == NULL) {
        result = OE_OUT_OF_MEMORY;
        goto exit;
    }
    memset((void *) padded_data, 0, m_data_size + padded_byte_count);
    // prepare new data buffer if padding is needed
    memcpy((void *) padded_data, (void *) m_data, m_data_size);
    // PKCS5 padding
    memset(
            (void *) (padded_data + m_data_size), padded_byte_count, padded_byte_count);
    m_data_size += padded_byte_count;

    // update data with new padded memory
    m_data = padded_data;

    total_size = sizeof(sealed_data_t) + m_data_size + key_info_size;

    // allocate the sealed data buffer inside enclave and fill with metadata
    // information
    m_sealed_data = (sealed_data_t *) malloc(total_size);
    if (m_sealed_data == NULL) {
        result = OE_OUT_OF_MEMORY;
        goto exit;
    }

    m_sealed_data->key_info_size = key_info_size;
    m_sealed_data->total_size = total_size;
    memcpy(m_sealed_data->opt_msg, opt_mgs, opt_msg_len);
    m_sealed_data->encrypted_data_len = m_data_size;
    m_sealed_data->original_data_size = original_data_size;

    // copy key info into the sealed_data_t
    memcpy(
            (void *) (m_sealed_data->encrypted_data + m_sealed_data->encrypted_data_len),
            (void *) key_info,
            key_info_size);
    exit:
    if (key_info)
        free(key_info);

    return result;
}
// Compute the sha256 hash of given data.
int ecall_dispatcher::Sha256(
        const uint8_t* data,
        size_t data_size,
        uint8_t sha256[HASH_VALUE_SIZE_IN_BYTES])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_update_ret(&ctx, data, data_size);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto exit;

    exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}

// This routine uses the mbed_tls library to derive an AES key from the input
// password and produces a password-based key.
int ecall_dispatcher::generate_password_key(
        const char* password,
        unsigned char* salt,
        unsigned char* key,
        unsigned int key_size)
{
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t* info_sha;
    int ret = 0;
    mbedtls_md_init(&sha_ctx);

    TRACE_ENCLAVE("generate_password_key");

    memset(key, 0, key_size);
    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == nullptr)
    {
        ret = 1;
        goto exit;
    }

    // setting up hash algorithm context
    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_md_setup() failed with -0x%04x", -ret);
        goto exit;
    }

    // Derive a key from a password using PBKDF2.
    // PBKDF2 (Password-Based Key Derivation Function 2) are key derivation
    // functions with a sliding computational cost, aimed to reduce the
    // vulnerability of encrypted keys to brute force attacks. See
    // (https://en.wikipedia.org/wiki/PBKDF2) for more details.
    ret = mbedtls_pkcs5_pbkdf2_hmac(
            &sha_ctx,                       // Generic HMAC context
            (const unsigned char*)password, // Password to use when generating key
            strlen((const char*)password),  // Length of password
            salt,                           // salt to use when generating key
            SALT_SIZE_IN_BYTES,             // size of salt
            100000,                         // iteration count
            key_size,                       // length of generated key in bytes
            key);                           // generated key
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_pkcs5_pbkdf2_hmac failed with -0x%04x", -ret);
        goto exit;
    }
    TRACE_ENCLAVE("Key based on password successfully generated");
    exit:
    mbedtls_md_free(&sha_ctx);
    return ret;
}

// Generate an encryption key: this is the key used to encrypt data
int ecall_dispatcher::generate_encryption_key(
        unsigned char* key,
        unsigned int key_size)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char pers[] = "EncryptionKey";
    int ret = 0;

    TRACE_ENCLAVE("generate_encryption_key:");

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(key, 0, key_size);

    // mbedtls_ctr_drbg_seed seeds and sets up the CTR_DRBG entropy source for
    // future reseeds.
    ret = mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            (unsigned char*)pers,
            sizeof(pers));
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_init failed with -0x%04x\n", -ret);
        goto exit;
    }

    // mbedtls_ctr_drbg_random uses CTR_DRBG to generate random data
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, key_size);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_random failed with -0x%04x\n", -ret);
        goto exit;
    }
    TRACE_ENCLAVE(
            "Encryption key successfully generated: a %d byte key (hex):  ",
            key_size);

    exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

// The encryption key is encrypted before it was written back to the encryption
// header as part of the encryption metadata.
int ecall_dispatcher::cipher_encryption_key(
        bool encrypt,
        unsigned char* input_data,
        unsigned int input_data_size,
        unsigned char* encrypt_key,
        unsigned char* iv,
        unsigned char* output_data,
        unsigned int output_data_size)
{
    int ret = 0;
    (void)output_data_size;
    mbedtls_aes_context aescontext;

    TRACE_ENCLAVE(
            "cipher_encryption_key: %s", encrypt ? "encrypting" : "decrypting");

    // init context
    mbedtls_aes_init(&aescontext);

    // set aes key
    if (encrypt)
    {
        ret = mbedtls_aes_setkey_enc(
                &aescontext, encrypt_key, ENCRYPTION_KEY_SIZE);
    }
    else
    {
        ret = mbedtls_aes_setkey_dec(
                &aescontext, encrypt_key, ENCRYPTION_KEY_SIZE);
    }
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_setkey_enc/dec failed with %d", ret);
        goto exit;
    }

    ret = mbedtls_aes_crypt_cbc(
            &aescontext,
            encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
            input_data_size, // input data length in bytes,
            iv,              // Initialization vector (updated after use)
            input_data,
            output_data);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_crypt_cbc failed with %d", ret);
    }
    exit:
    // free aes context
    mbedtls_aes_free(&aescontext);
    TRACE_ENCLAVE("ecall_dispatcher::cipher_encryption_key");
    return ret;
}

// For an encryption operation, the encryptor creates encryption metadata for
// writing back to the encryption header, which includes the following fields:
// digest: a hash value of the password
// key: encrypted version of the encryption key
//
// Operations involves the following operations:
//  1)derive a key from the password
//  2)produce a encryption key
//  3)generate a digest for the password
//  4)encrypt the encryption key with a password key
//
int ecall_dispatcher::prepare_encryption_header(
        encryption_header_t* header,
        string password)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret = 0;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES]; // sha256 digest of password
    unsigned char
            password_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; // password generated key,
    // used to encrypt
    // encryption_key using
    // AES256-CBC
    unsigned char
            encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; // encrypted encryption_key
    // using AES256-CBC
    unsigned char salt[SALT_SIZE_IN_BYTES];
    const char seed[] = "file_encryptor_sample";

    if (header == nullptr)
    {
        TRACE_ENCLAVE("prepare_encryption_header() failed with null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Initialize CTR-DRBG seed
    ret = mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            (const unsigned char*)seed,
            strlen(seed));
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_seed() failed with -0x%04x", -ret);
        goto exit;
    }

    // Generate random salt
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, sizeof(salt));
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_random() failed with -0x%04x", -ret);
        goto exit;
    }
    memcpy(header->salt, salt, sizeof(salt));

    TRACE_ENCLAVE("prepare_encryption_header");
    // derive a key from the password using PBDKF2
    ret = generate_password_key(
            password.c_str(), salt, password_key, sizeof(password_key));
    if (ret != 0)
    {
        TRACE_ENCLAVE("password_key");
        for (unsigned int i = 0; i < sizeof(password_key); i++)
            TRACE_ENCLAVE(
                    "password_key[%d] =0x%02x", i, (unsigned int)(password_key[i]));
        goto exit;
    }

    // produce a encryption key
    TRACE_ENCLAVE("produce a encryption key");
    ret = generate_encryption_key(
            (unsigned char*)m_encryption_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            TRACE_ENCLAVE(
                    "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        goto exit;
    }

    // generate a digest for the password
    TRACE_ENCLAVE("generate a digest for the password");
    ret = Sha256((const uint8_t*)password.c_str(), password.length(), digest);
    if (ret)
    {
        TRACE_ENCLAVE("Sha256 failed with %d", ret);
        goto exit;
    }

    memcpy(header->digest, digest, sizeof(digest));

    // encrypt the encryption key with a password key
    TRACE_ENCLAVE("encrypt the encryption key with a psswd key");
    ret = cipher_encryption_key(
            ENCRYPT_OPERATION,
            m_encryption_key,
            ENCRYPTION_KEY_SIZE_IN_BYTES,
            password_key,
            salt, // iv for encryption, decryption. In this sample we use
            // the salt in encryption header as iv.
            encrypted_key,
            sizeof(encrypted_key));
    if (ret != 0)
    {
        TRACE_ENCLAVE("EncryptEncryptionKey failed with [%d]", ret);
        goto exit;
    }
    memcpy(header->encrypted_key, encrypted_key, sizeof(encrypted_key));
    TRACE_ENCLAVE("Done with prepare_encryption_header successfully.");
    exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

// Parse an input header for validating the password and getting the encryption
// key in preparation for decryption/encryption operations
//  1)Check password by comparing their digests
//  2)reproduce a password key from the password
//  3)decrypt the encryption key with a password key
int ecall_dispatcher::parse_encryption_header(
        encryption_header_t* header,
        string password)
{
    int ret = 0;
    if (header == nullptr)
    {
        TRACE_ENCLAVE("parse_encryption_header() failed with a null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char password_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
    unsigned char salt[SALT_SIZE_IN_BYTES];

    // check password by comparing their digests
    ret =
            Sha256((const uint8_t*)m_password.c_str(), m_password.length(), digest);
    if (ret)
    {
        TRACE_ENCLAVE("Sha256 failed with %d", ret);
        goto exit;
    }

    if (memcmp(header->digest, digest, sizeof(digest)) != 0)
    {
        TRACE_ENCLAVE("incorrect password");
        ret = 1;
        goto exit;
    }

    memcpy(salt, header->salt, sizeof(salt));

    // derive a key from the password using PBDKF2
    ret = generate_password_key(
            password.c_str(), salt, password_key, sizeof(password_key));
    if (ret != 0)
    {
        TRACE_ENCLAVE("generate_password_key failed with %d", ret);
        goto exit;
    }

    // decrypt the "encrypted encryption key" using the password key
    ret = cipher_encryption_key(
            DECRYPT_OPERATION,
            header->encrypted_key,
            ENCRYPTION_KEY_SIZE_IN_BYTES,
            password_key,
            salt, // iv for encryption, decryption. In this sample we use
            // the salt in encryption header as iv.
            (unsigned char*)m_encryption_key,
            ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            TRACE_ENCLAVE(
                    "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        goto exit;
    }

    exit:
    return ret;
}

int ecall_dispatcher::process_encryption_header(encryption_header_t* header)
{
    int ret = 0;

    if (header == nullptr)
    {
        TRACE_ENCLAVE("process_encryption_header() failed with a null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    if (m_encrypt)
    {
        // allocate memory for the header and it will be copied back to
        // the host
        m_header = (encryption_header_t*)malloc(sizeof(encryption_header_t));
        if (m_header == nullptr)
        {
            TRACE_ENCLAVE("malloc failed");
            ret = 1;
            goto exit;
        }

        ret = prepare_encryption_header(m_header, m_password);
        if (ret != 0)
        {
            TRACE_ENCLAVE("prepare_encryption_header failed with %d", ret);
            goto exit;
        }
        memcpy(header, m_header, sizeof(encryption_header_t));
    }
    else
    {
        ret = parse_encryption_header(m_header, m_password);
        if (ret != 0)
        {
            TRACE_ENCLAVE("parse_encryption_header failed with %d", ret);
            goto exit;
        }
    }
    exit:
    return ret;
}