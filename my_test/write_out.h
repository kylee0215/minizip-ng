#ifndef WRITE_OUT_H
#define WRITE_OUT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <time.h>
#include <inttypes.h> // for uint64_t

#include "zipcrypto.h"
#include "mz.h"

#define WRITEBUFFERSIZE (16384)
#define MAXFILENAME (256)

#define Z_BUFSIZE (64 * 1024)
#define VersionMadeBy (51)
#define VersionNeeded (51)

#define ZIP_OK                          (0)
#define ZIP_EOF                         (0)
#define ZIP_ERRNO                       (Z_ERRNO)
#define ZIP_PARAMERROR                  (-102)
#define ZIP_BADZIPFILE                  (-103)
#define ZIP_INTERNALERROR               (-104)

#define LOCALHEADERMAGIC    (0x04034b50)
#define CENTRALHEADERMAGIC  (0x02014b50)
#define ENDHEADERMAGIC      (0x06054b50)
#define ZIP64ENDHEADERMAGIC      (0x06064b50)
#define ZIP64ENDLOCHEADERMAGIC   (0x07064b50)
#define ZIP64DATADESCHEADERMAGIC   (0x08074b50)

typedef unsigned int uInt;
typedef unsigned long uLong;

#define RAND_HEAD_LEN 12

typedef struct {
	char filename[256];
	unsigned long crc32;
	unsigned long flag;
	int method;
	int encrypt;
	int zip64;
	uint64_t pos_zip64extrainfo;
	uint64_t totalCompressedData;
	uint64_t totalUncompressedData;
	uint64_t LocHdrSize;
	uint64_t loc_offset; // Relative offset of local file header for CEN
	uint64_t cen_offset; // Offset of start of central directory, relative to start of archive for EOCD
	union {
		uint16_t mod_time;
		struct {
			unsigned tm_sec:5;
			unsigned tm_min:6;
			unsigned tm_hour:5;
		};
	};
	union {
		uint16_t mod_date;
		struct {
			unsigned tm_mday:5;
			unsigned tm_mon:4;
			unsigned tm_year:7;
		};
	};
	uint16_t verifier;

	/* ZipCrypto */
	uint32_t crcForCrypting;
	uint32_t keys[3];	 /* keys defining the pseudo-random sequence */
	unsigned crypt_header_size;

	/* WinZip AES-256 */
	void *wzaes;
	int16_t aes_encryption_mode;
	int aes_version; // AE-1, AE-2
} zip_entry_info;

typedef struct {
	z_stream stream;
	uInt number_entry;
	int cur_entry;
	zip_entry_info entry[128];
	char out_zip[256];
	uLong cur_offset;
	uLong size_centraldir;
	unsigned char buffered_data[Z_BUFSIZE];
	uInt pos_in_buffered_data;
	uLong Zip64EOCDRecord_offset;

	// output zip file function pointer
	size_t (*write)(char *buf, uLong size, void *zi);
} zip64_info;

#endif
