#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>

#define MZ_AES_KEYING_ITERATIONS    (1000)
#define MZ_AES_SALT_LENGTH(MODE)    (4 * (MODE & 3) + 4)
#define MZ_AES_SALT_LENGTH_MAX      (16)
#define MZ_AES_PW_LENGTH_MAX        (128)
#define MZ_AES_PW_VERIFY_SIZE       (2)
#define MZ_AES_AUTHCODE_SIZE        (10)

typedef struct my_wzaes_s {
    mz_stream       stream;
    int32_t         mode;
    int32_t         error;
    int16_t         initialized;
    uint8_t         buffer[UINT16_MAX];
    int64_t         total_in;
    int64_t         max_total_in;
    int64_t         total_out;
    int16_t         encryption_mode;
    const char      *password;
    void            *aes;
    uint32_t        crypt_pos;
    uint8_t         crypt_block[AES_BLOCK_SIZE];
    void            *hmac;
    uint8_t         nonce[AES_BLOCK_SIZE];
} my_wzaes;

void *my_wzaes_new(void)
{
	mz_wzaes *wzaes = malloc(sizeof(my_wzaes));

	return wzaes;
}

void my_wzaes_set_password(void *ptr, char *password)
{
	my_wzaes *wzaes = ptr;
	wzaes->password = password;
}

void my_wzaes_set_encryption_mode(void *ptr, int64_t mode)
{
	my_wzaes *wzaes = ptr;
	wzaes->encryption_mode = mode;
}

int32_t mz_stream_wzaes_open(void *stream, const char *path, int32_t mode) {
    mz_stream_wzaes *wzaes = (mz_stream_wzaes *)stream;
    uint16_t salt_length = 0;
    uint16_t password_length = 0;
    uint16_t key_length = 0;
    uint8_t kbuf[2 * MZ_AES_KEY_LENGTH_MAX + MZ_AES_PW_VERIFY_SIZE];
    uint8_t verify[MZ_AES_PW_VERIFY_SIZE];
    uint8_t verify_expected[MZ_AES_PW_VERIFY_SIZE];
    uint8_t salt_value[MZ_AES_SALT_LENGTH_MAX];
    const char *password = path;

    wzaes->total_in = 0;
    wzaes->total_out = 0;
    wzaes->initialized = 0;

    if (password == NULL)
        password = wzaes->password;
    if (password == NULL)
        return MZ_PARAM_ERROR;
    password_length = (uint16_t)strlen(password);
    if (password_length > MZ_AES_PW_LENGTH_MAX)
        return MZ_PARAM_ERROR;

    if (wzaes->encryption_mode < 1 || wzaes->encryption_mode > 3)
        return MZ_PARAM_ERROR;

    salt_length = MZ_AES_SALT_LENGTH(wzaes->encryption_mode);

    if (mode & MZ_OPEN_MODE_WRITE) {
        mz_crypt_rand(salt_value, salt_length);
    } else if (mode & MZ_OPEN_MODE_READ) {
        if (mz_stream_read(wzaes->stream.base, salt_value, salt_length) != salt_length)
            return MZ_READ_ERROR;
    }

    key_length = MZ_AES_KEY_LENGTH(wzaes->encryption_mode);

    /* Derive the encryption and authentication keys and the password verifier */
    mz_crypt_pbkdf2((uint8_t *)password, password_length, salt_value, salt_length,
        MZ_AES_KEYING_ITERATIONS, kbuf, 2 * key_length + MZ_AES_PW_VERIFY_SIZE);

    /* Initialize the encryption nonce and buffer pos */
    wzaes->crypt_pos = MZ_AES_BLOCK_SIZE;
    memset(wzaes->nonce, 0, sizeof(wzaes->nonce));

    /* Initialize for encryption using key 1 */
    mz_crypt_aes_reset(wzaes->aes);
    mz_crypt_aes_set_mode(wzaes->aes, wzaes->encryption_mode);
    mz_crypt_aes_set_encrypt_key(wzaes->aes, kbuf, key_length);

    /* Initialize for authentication using key 2 */
    mz_crypt_hmac_reset(wzaes->hmac);
    mz_crypt_hmac_set_algorithm(wzaes->hmac, MZ_HASH_SHA1);
    mz_crypt_hmac_init(wzaes->hmac, kbuf + key_length, key_length);

    memcpy(verify, kbuf + (2 * key_length), MZ_AES_PW_VERIFY_SIZE);

    if (mode & MZ_OPEN_MODE_WRITE) {
        if (mz_stream_write(wzaes->stream.base, salt_value, salt_length) != salt_length)
            return MZ_WRITE_ERROR;

        wzaes->total_out += salt_length;

        if (mz_stream_write(wzaes->stream.base, verify, MZ_AES_PW_VERIFY_SIZE) != MZ_AES_PW_VERIFY_SIZE)
            return MZ_WRITE_ERROR;

        wzaes->total_out += MZ_AES_PW_VERIFY_SIZE;
    } else if (mode & MZ_OPEN_MODE_READ) {
        wzaes->total_in += salt_length;

        if (mz_stream_read(wzaes->stream.base, verify_expected, MZ_AES_PW_VERIFY_SIZE) != MZ_AES_PW_VERIFY_SIZE)
            return MZ_READ_ERROR;

        wzaes->total_in += MZ_AES_PW_VERIFY_SIZE;

        if (memcmp(verify_expected, verify, MZ_AES_PW_VERIFY_SIZE) != 0)
            return MZ_PASSWORD_ERROR;
    }

    wzaes->mode = mode;
    wzaes->initialized = 1;

    return MZ_OK;
}
