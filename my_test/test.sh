#!/bin/bash

gcc gz2.c mz_strm_wzaes.c mz_crypt.c mz_crypt_openssl.c zipcrypto.c -g -o gz2 -lz -lssl -lcrypto
rm test.zip > /dev/null 2>&1
./gz2 test.zip test.txt test2.txt
# ./gz2 test.zip test.txt
