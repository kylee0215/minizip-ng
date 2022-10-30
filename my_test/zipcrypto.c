#include "zipcrypto.h"

size_t zipcrypto_encrypt_init(uint8_t *header, uint32_t *pkeys, char *password,
        uint16_t verifier)
{
    int i, c, t;

    if (password == NULL)
        return 0;

    init_keys(pkeys, password);
    
    /* First generate RAND_HEAD_LEN - 2 random bytes. Encrypt output of rand(),
     * since rand() is poorly implemented
     */
    for (i = 0; i < RAND_HEAD_LEN - 2; i++) {
        c = (rand() >> 7) & 0xff;
        header[i] = (uint8_t)crypt_encode(pkeys, c, t);
    }

    /* Encrypt random header (last two bytes is high word of crc or dos_time,
     * depend on the flag bit 3)
     */
    init_keys(pkeys, password);
    for (i = 0; i < RAND_HEAD_LEN - 2; i++)
        header[i] = crypt_encode(pkeys, header[i], t);

    uint8_t verify1 = (uint8_t)((verifier >> 8) & 0xff);
    uint8_t verify2 = (uint8_t)(verifier & 0xff);

    header[i++] = crypt_encode(pkeys, verify1, t);
    header[i++] = crypt_encode(pkeys, verify2, t);

    return i;
}
