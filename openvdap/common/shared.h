#ifndef _SHARED_H
#define _SHARED_H

#include <stddef.h>
#define POLICY_UNIQUE 1
#define POLICY_PRODUCT 2

#define MAX_OPT_MESSAGE_LEN 128
#define IV_SIZE 16
#define SIGNATURE_LEN 32

// errors shared by host and enclaves
#define ERROR_SIGNATURE_VERIFY_FAIL 1
#define ERROR_OUT_OF_MEMORY 2
#define ERROR_GET_SEALKEY 3
#define ERROR_SIGN_SEALED_DATA_FAIL 4
#define ERROR_CIPHER_ERROR 5
#define ERROR_UNSEALED_DATA_FAIL 6

typedef struct _sealed_data_t {
    size_t total_size;
    unsigned char signature[SIGNATURE_LEN];
    unsigned char opt_msg[MAX_OPT_MESSAGE_LEN];
    unsigned char iv[IV_SIZE];
    size_t key_info_size;
    size_t original_data_size;
    size_t encrypted_data_len;
    unsigned char encrypted_data[];
} sealed_data_t;


#define  OPENVDAP_DEBUG
#define  OPENVDAP_INFO
#define  OPENVDAP_LOG


#ifdef OPENVDAP_INFO
#define INFO() \
    fprintf(stderr, ">>>LOG: %s: %s: %d \n", __FILE__,__func__, __LINE__);
#else
#define INFO(msg) do{}while(0);
#endif

#ifdef OPENVDAP_LOG
#define LOG(msg) \
    do{\
    fprintf(stderr, "===INFO: %s: %s: %d => ", __FILE__,__func__, __LINE__); \
    fprintf(stderr, "%s\n", msg);\
    }while(0);
#else
#define LOG(msg) do{}while(0);
#endif

#define LOG_INT(msg) \
    do{\
    fprintf(stderr, "===INFO: %s: %s: %d => ", __FILE__,__func__, __LINE__); \
    fprintf(stderr, "%d\n", msg);\
    }while(0);

#define ERROR() \
    do{\
    fprintf(stderr, "XXX ERROR: %s: %s: %d => ", __FILE__,__func__, __LINE__); \
    }while(0);

#ifdef OPENVDAP_DEBUG
#define DEBUG(msg) \
    do{\
    fprintf(stderr, "###DEBUG: %s: %s: %d => ", __FILE__,__func__, __LINE__); \
    fprintf(stderr, "%s\n", msg);\
    }while(0);
#else
#define DEBUG(msg) do{}while(0);
#endif

#define TRACE_ENCLAVE(fmt, ...) \
    printf("ENCLAVE: %s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)


#define TRACE_HOST(fmt, ...) \
    printf("HOST: %s(%d): " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)



#define HASH_VALUE_SIZE_IN_BYTES 32 // sha256 hashing algorithm
#define ENCRYPTION_KEY_SIZE 256     // AES256-CBC encryption algorithm
#define ENCRYPTION_KEY_SIZE_IN_BYTES (ENCRYPTION_KEY_SIZE / 8)
#define IV_SIZE 16 // determined by AES256-CBC
#define SALT_SIZE_IN_BYTES IV_SIZE

// encryption_header_t contains encryption metadata used for decryption
// file_data_size: this is the size of the data in an input file, excluding the
// header digest: this field contains hash value of a password
// encrypted_key: this is the encrypted version of the encryption key used for
//                encrypting and decrypting the data
// salt: The salt value used in deriving the password key.
//       It is also used as the IV for the encryption/decryption of the data.
typedef struct _encryption_header
{
    size_t file_data_size;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
    unsigned char salt[SALT_SIZE_IN_BYTES];
} encryption_header_t;



#endif /* _SHARED_H */
