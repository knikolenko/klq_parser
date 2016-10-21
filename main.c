#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define KLQB_SIGNATURE 0x42514C4B

#define GET_DWORD(x) (*(DWORD*)x)

const char XorGamma[] = {0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC};

typedef struct {
	uint32_t Signature;
	uint32_t One;
	uint32_t HeaderSize;
} THeader;

typedef struct {
	size_t Offset;
	size_t Size;
} TMetaDataInfo;

unsigned long long swapByteOrder64(unsigned long long ull)
{
    return (ull >> 56) |
          ((ull<<40) & 0x00FF000000000000) |
          ((ull<<24) & 0x0000FF0000000000) |
          ((ull<<8) & 0x000000FF00000000) |
          ((ull>>8) & 0x00000000FF000000) |
          ((ull>>24) & 0x0000000000FF0000) |
          ((ull>>40) & 0x000000000000FF00) |
          (ull << 56);
}

void HexDump(uint8_t *pInput, size_t cbInput)
{
  DWORD nBufSize = 0;
	CHAR *pOutput = NULL;

  if (!pInput || cbInput == 0)
    return;

  if (CryptBinaryToStringA(pInput, cbInput, CRYPT_STRING_HEXASCII, NULL, &nBufSize) && nBufSize > 0)
    if ((pOutput = malloc(nBufSize+1)) != NULL)
      CryptBinaryToStringA(pInput, cbInput, CRYPT_STRING_HEXASCII, pOutput, &nBufSize);

	printf("%s", pOutput);
	free(pOutput);

  return;
}

void Xor(uint8_t* buf, size_t cbBuf)
{
	if (!buf || cbBuf == 0)
		return;

	for (size_t i = 0; i < cbBuf; i++) {
		*buf++ ^= XorGamma[i % sizeof(XorGamma)];
	}
}

TMetaDataInfo *Parse34(uint8_t *buffer, SIZE_T nInputSize)
{
	if (!buffer || nInputSize == 0)
		return NULL;

	TMetaDataInfo *meta = malloc(sizeof(TMetaDataInfo));
	if (!meta)
		return NULL;

	meta->Offset = GET_DWORD(&buffer[0x0C]);
	meta->Size   = GET_DWORD(&buffer[0x18]);
	return meta;
}

TMetaDataInfo *Parse40(uint8_t *buffer, SIZE_T nInputSize)
{
	if (!buffer || nInputSize == 0)
		return NULL;

	TMetaDataInfo *meta = malloc(sizeof(TMetaDataInfo));
	if (!meta)
		return NULL;

	meta->Offset = GET_DWORD(&buffer[0x10]);
	meta->Size   = GET_DWORD(&buffer[0x20]);

	return meta;
}

void ParseMetaData(uint8_t *buffer, SIZE_T nInputSize, TMetaDataInfo *lpMetaData)
{
	if (!buffer || nInputSize == 0 || !lpMetaData || lpMetaData->Size == 0)
		return;

	SIZE_T nPos = 0;
	while (nPos < lpMetaData->Size)
	{
		SIZE_T nRealPos = lpMetaData->Offset + nPos; 
		if (nRealPos > nInputSize)
			break;

		DWORD dwBlobLen = GET_DWORD(&buffer[nRealPos]);
		//printf("%08x\n", dwBlobLen);

		nRealPos += sizeof(dwBlobLen);

		Xor(&buffer[nRealPos], dwBlobLen);
		DWORD dwNameLen = GET_DWORD(&buffer[nRealPos]);

		nRealPos += sizeof(dwNameLen);

		printf("%*s\n", dwNameLen, &buffer[nRealPos]);
		uint8_t *lpVal = &buffer[nRealPos + dwNameLen];

		if (!memcmp(&buffer[nRealPos], "cNP_QB_FULLNAME", dwNameLen))
		{
			printf("%ls\n", (WCHAR*)lpVal);
			puts("");
			nPos += dwBlobLen + sizeof(DWORD);
			continue;
		}

		if (strstr((CHAR*)&buffer[nRealPos], "_TIME"))
		{
			uint64_t uiL = *(uint64_t *)lpVal;
			uint32_t ui = uiL / 100000000LL;
			ui -= 31556926 * 1969;
			ui += 60 * 60 + 21 * 60 + 34;

			//HexDump((CHAR*)&ui, 4);
			//printf("%llu %u\n", uiL, ui);

			struct tm *tmval = gmtime(&ui);
			char outbuf[30] = { 0 };
			strftime(outbuf, sizeof(outbuf), "%d.%m.%Y %T", tmval);
			printf("%s\n", outbuf);
			puts("");
			nPos += dwBlobLen + sizeof(DWORD);
			continue;
		}

		DWORD dwValLen = (dwBlobLen - dwNameLen - sizeof(DWORD));
		HexDump(lpVal, dwValLen);
		puts("");

		nPos += dwBlobLen + sizeof(DWORD);
	}
}

int main (int argc, char **argv)
{
	HANDLE hInput = NULL, hOutput = NULL;
	SIZE_T nInputSize = 0, nWr;
	uint8_t *buffer = NULL;
	THeader *lpHeader = NULL;
	TMetaDataInfo *lpMetaData = NULL;

	if (argc != 2) {
		puts("Usage:");
		printf("  %s <file_name>\n\n", argv[0]);
		return 0;
	}

	hInput  = CreateFile(argv[1], GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hInput == INVALID_HANDLE_VALUE) {
		puts("Can not open file!");
		return 0;
	}

	nInputSize = GetFileSize(hInput, 0);
	buffer = VirtualAlloc(NULL, nInputSize + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buffer) {
		puts("No enough memory!");
		CloseHandle(hInput);
		return 0;
	}
	ReadFile(hInput, &buffer[0], nInputSize, &nWr, 0);
	CloseHandle(hInput);

	lpHeader = (THeader *)buffer;
	if (lpHeader->Signature != KLQB_SIGNATURE) {
		puts("This file is not KLQB format!");
		goto deinit;
	}

	switch (lpHeader->HeaderSize)
	{
		case 0x34:
		{
			lpMetaData = Parse34(buffer, nInputSize);
			break;
		}
		case 0x40:
		{
			lpMetaData = Parse40(buffer, nInputSize);
			break;
		}
		default:
		{
			puts("Unknown format file!");
			goto deinit;
		}
	}

	if (!lpMetaData)
	{
		puts("Meta data not found!");
		goto deinit;
	}
	else
	{
		ParseMetaData(buffer, nInputSize, lpMetaData);
	}

	CHAR *lpOutFName = malloc(strlen(argv[1]) + 5);
	if (!lpOutFName)
	{
		puts("Error unpacking!");
		goto deinit;
	}

	size_t binSize = lpMetaData->Offset - lpHeader->HeaderSize;
	Xor(&buffer[lpHeader->HeaderSize], binSize);

	sprintf(lpOutFName, "%s.unp", argv[1]);
	FILE *fOut = fopen(lpOutFName, "wb");
	fwrite(&buffer[lpHeader->HeaderSize], 1, binSize, fOut);
	fclose(fOut);
	free(lpOutFName);

deinit:
	VirtualFree(buffer, nInputSize + 1, MEM_RELEASE | MEM_DECOMMIT);
	return 0;
}
