// Quietus.cpp : Defines the entry point for the console application.
//

#include "assert.h"
#include "string.h"
#include <stdlib.h>
#include <stdio.h>
#include <mumpublic.h>
#include "windows.h"

#define NUM_TEST_FILES 2
#define NUM_ENTROPY_ITERATIONS 25000
#define TEST_MUM_NUM_THREADS 8

// store the file as binary chunk
uint8_t *urFileData[NUM_TEST_FILES];
// load the same size decrypted version of encrypted file
uint8_t *deFileData[NUM_TEST_FILES];
size_t fileLength[NUM_TEST_FILES];
int bitsSet[256];

uint8_t *largePlaintext = nullptr;
uint8_t *largeEncrypt = nullptr;
uint8_t *largeDecrypt = nullptr;


// original files
char *testfile[NUM_TEST_FILES] = {
    "..\\testfiles\\image.jpg",
    "..\\testfiles\\music.m4a"
};

// encrypted files
char *testfileE[NUM_TEST_FILES] = {
    "..\\testfiles\\imageEncrypted.jpg",
    "..\\testfiles\\musicEncrypted.m4a"
};

// decrypted files
char *testfileD[NUM_TEST_FILES] = {
    "..\\testfiles\\imageDecrypted.jpg",
    "..\\testfiles\\musicDecrypted.m4a"
};

// #define CREATE_REFERENCE_FILES
#define NUM_REFERENCE_FILES 2
char *referenceFileKey = "..\\referencefiles\\key.bin";
char *referenceTempFile = "..\\referencefiles\\temp";
char *referenceFiles[NUM_REFERENCE_FILES] = {
    "..\\referencefiles\\image.jpg",
    "..\\referencefiles\\constitution.pdf"
};


#define TEST_NUM_ENGINES 4
EMumEngineType engineList[TEST_NUM_ENGINES] = {
    MUM_ENGINE_TYPE_CPU,
	MUM_ENGINE_TYPE_CPU_MT,
	MUM_ENGINE_TYPE_GPU_A,
	MUM_ENGINE_TYPE_GPU_B,
};

// the GPU-B engine only supports 4K block size
EMumBlockType firstTestBlockTypeList[TEST_NUM_ENGINES] = {
    MUM_BLOCKTYPE_128,
    MUM_BLOCKTYPE_128,
    MUM_BLOCKTYPE_128,
    MUM_BLOCKTYPE_4096
};

// We'll only profile 4K block size for GPU-A
EMumBlockType firstProfilingBlockTypeList[TEST_NUM_ENGINES] = {
    MUM_BLOCKTYPE_128,
    MUM_BLOCKTYPE_128,
    MUM_BLOCKTYPE_4096,
    MUM_BLOCKTYPE_4096
};

char *engineName[TEST_NUM_ENGINES] = {
    "CPU-engine",
    "CPU-MT-engine",
    "GPU-A-engine",
    "GPU-B-engine",
};

// #define TEST_WITH_PADDING_OFF
#ifdef TEST_WITH_PADDING_OFF

#define TEST_NUM_PADDING_TYPES 2
EMumPaddingType paddingList[TEST_NUM_PADDING_TYPES] = {
    MUM_PADDING_TYPE_ON,
    MUM_PADDING_TYPE_OFF,
};

char *paddingName[TEST_NUM_PADDING_TYPES] = {
    "padding-on",
    "padding-off",
};

#else

#define TEST_NUM_PADDING_TYPES 1
EMumPaddingType paddingList[TEST_NUM_PADDING_TYPES] = {
    MUM_PADDING_TYPE_ON
};

char *paddingName[TEST_NUM_PADDING_TYPES] = {
    "padding-on"
};

#endif



double pcfreq = 0.0;
__int64 counterstart = 0;

void startCounter()
{
    LARGE_INTEGER li;
    QueryPerformanceFrequency(&li);
    pcfreq = double(li.QuadPart) / 1000.0;
    QueryPerformanceCounter(&li);
    counterstart = li.QuadPart;
}

double getCounter()
{
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li);
    return double(li.QuadPart - counterstart)/pcfreq;
}

void fillRandomly(uint8_t *data, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++)
    {
        data[i] = (uint8_t) rand();
    }
}

void fillSequentially(uint8_t *data, uint32_t size)
{
    uint32_t *dst = (uint32_t *)data;
    for (uint32_t i = 0; i < size/4; i++)
    {
        dst[i] = i;
    }
}

bool loadFile(char *filename, uint8_t **data, size_t *length)
{
    FILE *f;
    size_t res, size;

    fopen_s(&f, filename, "rb");
    if (!f) return false;

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (*data != nullptr)
    {
        res = fread(*data, 1, size, f);
        fclose(f);
        if (res != size)
            return false;
        *length = size;
    }
    else
    {
        uint8_t *buffer = (uint8_t *)malloc(size);
        res = fread(buffer, 1, size, f);
        fclose(f);
        if (res != size)
            return false;
        *length = size;
        *data = buffer;
    }
    return true;
}


bool loadUrFiles()
{
    for (int i = 0; i < NUM_TEST_FILES; i++)
    {
        urFileData[i] = nullptr;
        if (!loadFile(testfile[i], &urFileData[i], &fileLength[i]))
            return false;
        deFileData[i] = (uint8_t *)malloc(fileLength[i]);
    }
    return true;
}

void init()
{
    int flags[8] = { 1, 2, 4, 8, 16, 32, 64, 128 };
    int i, bit;

    for (i = 0; i < 256; i++)
    {
        int total = 0;
        for (bit = 0; bit < 8; bit++)
        {
            if (i&flags[bit])
                total++;
        }
        bitsSet[i] = total;
    }

    uint32_t plaintextSize = 256000000;
    uint32_t encryptBufferSize = plaintextSize * 5 / 4;

    largePlaintext = new uint8_t[plaintextSize];
    largeEncrypt = new uint8_t[encryptBufferSize];
    largeDecrypt = new uint8_t[plaintextSize + 65536];
}

bool loadDeFiles(int index)
{
    size_t length;
    if (!loadFile(testfile[index], &deFileData[index], &length))
        return false;
    if (length != fileLength[index])
        return false;
    return true;
}

bool testFileEncrypt(void * engine, char *engineType)
{
    EMumError error;
    uint8_t clavier[MUM_KEY_SIZE];
    uint32_t encryptedBlockSize;

    error = MumEncryptedBlockSize(engine, &encryptedBlockSize);
    fillRandomly(clavier, MUM_KEY_SIZE);
    error = MumInitKey(engine, clavier);
    for (int i = 0; i < NUM_TEST_FILES; i++)
    {
        error = MumEncryptFile(engine, testfile[i], testfileE[i]);
        if (error != MUM_ERROR_OK)
            return false;
        error = MumDecryptFile(engine, testfileE[i], testfileD[i]);
        if (error != MUM_ERROR_OK)
            return false;

        if (!loadDeFiles(i))
        {
            printf("FAILED testFileEncrypt, engine %s, block size %d: can't load decrypt files\n",
                engineType, encryptedBlockSize);
            return false;
        }
        // printf("   compare original file with decrypted data, block size %d, size %zd\n", encryptedBlockSize, fileLength[i]);
        if (memcmp(urFileData[i], deFileData[i], fileLength[i]) != 0)
        {
            printf("FAILED testFileEncrypt, block size %d\n", encryptedBlockSize);
            return false;
        }
        printf("SUCCESS testFileEncrypt, block size %d, file %s\n", encryptedBlockSize, testfile[i]);
    }
    return true;
}

bool testReferenceFileDecrypt(void * engine, char *engineType, EMumBlockType blockType)
{
    EMumError error;
    uint32_t encryptedBlockSize;

    error = MumEncryptedBlockSize(engine, &encryptedBlockSize);
    if (error != MUM_ERROR_OK)
        return false;
    error = MumLoadKey(engine, referenceFileKey);
    if (error != MUM_ERROR_OK)
        return false;
    for (int i = 0; i < NUM_REFERENCE_FILES; i++)
    {
        // Determine name of encrypted file
        char encryptedname[512];
        error = MumCreateEncryptedFileName(blockType, referenceFiles[i], encryptedname, 512);
        if (error != MUM_ERROR_OK)
            return false;

        // Decrypt file into temp file
        error = MumDecryptFile(engine, encryptedname, referenceTempFile);
        if (error != MUM_ERROR_OK)
            return false;

        size_t originalLength;
        uint8_t *originalData = nullptr;
        if (!loadFile(referenceFiles[i], &originalData, &originalLength))
            return false;

        size_t decryptedLength;
        uint8_t *decryptedData = nullptr;
        if (!loadFile(referenceTempFile, &decryptedData, &decryptedLength))
            return false;

        if (originalLength != decryptedLength)
        {
            printf("FAILED testReferenceFileDecrypt, length do not match: %zd %zd\n", originalLength, decryptedLength);
            return false;
        }

        // printf("   compare original reference file with decrypted data, block size %d, size %zd\n", encryptedBlockSize, originalLength);
        if (memcmp(originalData, decryptedData, originalLength) != 0)
        {
            printf("FAILED testReferenceFileDecrypt, block size %d\n", encryptedBlockSize);
            return false;
        }
        printf("SUCCESS testReferenceFileDecrypt, block size %d, file %s\n", encryptedBlockSize, encryptedname);

        // cleanup
        free(originalData);
        free(decryptedData);
    }
    return true;
}

bool analyzeBitsChange(uint32_t bitsChanged, uint32_t bitsTotal, uint32_t bytesChanged, uint32_t bytesTotal)
{
    float bitsPercent = (float)bitsChanged *100.0f / (float)bitsTotal;
    float bytesPart = (float)bytesChanged *256.0f / (float)bytesTotal;
    bool success = true;
    if (bytesTotal > MUM_KEY_SIZE)
    {
        if (bitsPercent < 49)
            success = false;
        if (bitsPercent > 51)
            success = false;
        if (bytesPart < 254.8f)
            success = false;
        if (bytesPart > 255.2f)
            success = false;
    }
    else
    {
        if (bitsPercent < 48)
            success = false;
        if (bitsPercent > 52)
            success = false;
        if (bytesPart < 253.0f)
            success = false;
        //if (bytesPart > 255.9f)
        //    success = false;
    }
    if (!success)
        printf("   bits %f, bytes %f\n", bitsPercent, bytesPart);
    return success;
}

void createRandomBlocksWithOneBitDifference(uint8_t *block1, uint8_t *block2, uint32_t size)
{
	uint32_t byteOffset = rand() % size;
	uint32_t bitOffset = rand() & 0x7;

	fillRandomly(block1, size);
	memcpy(block2, block1, size);
	block2[byteOffset] ^= 1 << bitOffset;
}

/*

bool testEntropyNoPadding(void *engine, char *engineType)
{
	EMumError error;
	uint8_t plaintext1[4096];
	uint8_t plaintext2[4096];
	uint8_t encrypt1[4096];
	uint8_t encrypt2[4096];
	uint8_t decrypt1[4096];
	uint8_t decrypt2[4096];
	uint32_t outlength, i, iter;
	uint32_t bitsChanged, bitsTotal;
	uint32_t bytesChanged, bytesTotal;
	uint32_t encryptedBlockSize, plaintextBlockSize;

    error = MumPlaintextBlockSize(engine, &plaintextBlockSize);
    error = MumEncryptedBlockSize(engine, &encryptedBlockSize);

	bitsChanged = 0;
	bitsTotal = 0;
	bytesChanged = 0,
		bytesTotal = 0;
	for (iter = 0; iter < NUM_ENTROPY_ITERATIONS*4; iter++)
	{
		createRandomBlocksWithOneBitDifference(plaintext1, plaintext2, plaintextBlockSize);

		error = MumEncrypt(engine, plaintext1, encrypt1, plaintextBlockSize, &outlength, 0);
		error = MumEncrypt(engine, plaintext2, encrypt2, plaintextBlockSize, &outlength, 0);
		error = MumDecrypt(engine, encrypt1, decrypt1, encryptedBlockSize, &outlength);
		error = MumDecrypt(engine, encrypt2, decrypt2, encryptedBlockSize, &outlength);
		// first, reality check; make sure both encryptions return same plaintext
		for (i = 0; i < plaintextBlockSize; i++)
		{
			assert(decrypt1[i] == plaintext1[i]);
			assert(decrypt2[i] == plaintext2[i]);
		}
		// Now, check deltas between bytes and deltas between bits
		// 255/256 of bytes should be different if blocks are 'random
		// 50% of bits should be different
		for (i = 0; i < encryptedBlockSize; i++)
		{
			if (encrypt1[i] != encrypt2[i])
				bytesChanged++;
			bitsChanged += bitsSet[encrypt1[i] ^ encrypt2[i]];
			bytesTotal++;
			bitsTotal += 8;
		}
	}
	bool success = analyzeBitsChange(bitsChanged, bitsTotal, bytesChanged, bytesTotal);
	if (!success)
	{
		printf("FAILED testEntropy, engine %s, block size %d\n", engineType, encryptedBlockSize);
		return true;
	}

	printf("SUCCESS testEntropy, engine %s, block size %d\n",
		engineType, encryptedBlockSize);

	return true;
}*/

bool testEntropy(void *engine, char *engineType, EMumPaddingType paddingType)
{
    EMumError error;
    uint8_t plaintext[4096];
    uint8_t encrypt1[4096];
    uint8_t encrypt2[4096];
    uint8_t decrypt1[4096];
    uint8_t decrypt2[4096];
    uint32_t outlength, i, iter;
    uint32_t bitsChanged, bitsTotal;
    uint32_t bytesChanged, bytesTotal;

	if (paddingType == MUM_PADDING_TYPE_OFF)
        return true;  

    uint32_t encryptedBlockSize, plaintextBlockSize;
    error = MumPlaintextBlockSize(engine, &plaintextBlockSize);
    error = MumEncryptedBlockSize(engine, &encryptedBlockSize);

    bitsChanged = 0;
    bitsTotal = 0;
    bytesChanged = 0,
    bytesTotal = 0;
    for (iter = 0; iter < NUM_ENTROPY_ITERATIONS; iter++)
    {
        fillRandomly(plaintext, plaintextBlockSize);
        error = MumEncrypt(engine, plaintext, encrypt1, plaintextBlockSize, &outlength, 0);
        error = MumEncrypt(engine, plaintext, encrypt2, plaintextBlockSize, &outlength, 0);
        error = MumDecrypt(engine, encrypt1, decrypt1, encryptedBlockSize, &outlength);
        error = MumDecrypt(engine, encrypt2, decrypt2, encryptedBlockSize, &outlength);
        // first, reality check; make sure both encryptions return same plaintext
        for (i = 0; i < plaintextBlockSize; i++)
        {
            if (decrypt1[i] != plaintext[i])
            {
                printf("FAILED testEntropy A, engine %s, plaintextSize %d, decrypted %d, index %d\n",
                    engineType, plaintextBlockSize, outlength, i);
                return false;
            }

            if (decrypt2[i] != plaintext[i])
            {
                printf("FAILED testEntropy B, engine %s, plaintextSize %d, decrypted %d, index %d\n",
                    engineType, plaintextBlockSize, outlength, i);
                return false;
            }
        }
        // Now, check deltas between bytes and deltas between bits
        // 255/256 of bytes should be different if blocks are 'random
        // 50% of bits should be different
        for (i = 0; i < encryptedBlockSize; i++)
        {
            if (encrypt1[i] != encrypt2[i])
                bytesChanged++;
            bitsChanged += bitsSet[encrypt1[i] ^ encrypt2[i]];
            bytesTotal++;
            bitsTotal += 8;
        }
    }

    bool success = analyzeBitsChange(bitsChanged, bitsTotal, bytesChanged, bytesTotal);
    if (!success)
    {
        printf("FAILED testEntropy, engine %s, block size %d\n", engineType, encryptedBlockSize);
        return false;
    }

    printf("SUCCESS testEntropy, engine %s, block size %d\n",
        engineType, encryptedBlockSize);


    // Do entropy test when plaintext consists just of zeros
    bitsChanged = 0;
    bitsTotal = 0;
    bytesChanged = 0,
    bytesTotal = 0;
    memset(plaintext, 0, plaintextBlockSize);
    for (iter = 0; iter < NUM_ENTROPY_ITERATIONS; iter++)
    {
        error = MumEncrypt(engine, plaintext, encrypt1, plaintextBlockSize, &outlength, 0);
        error = MumEncrypt(engine, plaintext, encrypt2, plaintextBlockSize, &outlength, 0);
        error = MumDecrypt(engine, encrypt1, decrypt1, encryptedBlockSize, &outlength);
        error = MumDecrypt(engine, encrypt2, decrypt2, encryptedBlockSize, &outlength);
        // first, reality check; make sure both encryptions return same plaintext
        for (i = 0; i < plaintextBlockSize; i++)
        {
            if (decrypt1[i] != plaintext[i])
            {
                printf("FAILED testEntropy C, engine %s, plaintextSize %d, decrypted %d, index %d\n",
                    engineType, plaintextBlockSize, outlength, i);
                return false;
            }
            if (decrypt2[i] != plaintext[i])
            {
                printf("FAILED testEntropy D, engine %s, plaintextSize %d, decrypted %d, index %d\n",
                    engineType, plaintextBlockSize, outlength, i);
                return false;
            }
        }
        // Now, check deltas between bytes and deltas between bits
        // 255/256 of bytes should be different if blocks are 'random'
        // 50% of bits should be different
        for (i = 0; i < encryptedBlockSize; i++)
        {
            if (encrypt1[i] != encrypt2[i])
                bytesChanged++;
            bitsChanged += bitsSet[encrypt1[i] ^ encrypt2[i]];
            bytesTotal++;
            bitsTotal += 8;
        }
    }

    success = analyzeBitsChange(bitsChanged, bitsTotal, bytesChanged, bytesTotal);
    if (!success)
    {
        printf("FAILED zeroed plaintext testEntropy, engine %s, block size %d\n", engineType, encryptedBlockSize);
        return false;
    }

    printf("SUCCESS zeroed plaintext testEntropy, engine %s, block size %d\n",
        engineType, encryptedBlockSize);

    return true;
}

bool testEntropySubkeyPair(void *engine, int index1, int index2)
{
    EMumError error;
    uint8_t subkey1[MUM_KEY_SIZE];
    uint8_t subkey2[MUM_KEY_SIZE];
    error = MumGetSubkey(engine, index1, subkey1);
    if (error != MUM_ERROR_OK)
        return false;
    error = MumGetSubkey(engine, index2, subkey2);
    if (error != MUM_ERROR_OK)
        return false;


    uint32_t bitsChanged = 0;
    uint32_t bitsTotal = 0;
    uint32_t bytesChanged = 0;
    uint32_t bytesTotal = 0;
    for (int i = 0; i < MUM_KEY_SIZE; i++)
    {
        if (subkey1[i] != subkey2[i])
            bytesChanged++;
        bitsChanged += bitsSet[subkey1[i] ^ subkey2[i]];
        bytesTotal++;
        bitsTotal += 8;
    }
    bool success = analyzeBitsChange(bitsChanged, bitsTotal, bytesChanged, bytesTotal);
    if (!success)
    {
        printf("FAILED testEntropySubkeyPair\n");
        return false;
    }
    return true;
}




bool testSubkeyEntropy(void *engine, char *engineType, EMumPaddingType paddingType)
{
    if (paddingType == MUM_PADDING_TYPE_OFF)
        return true;

    for (int i = 0; i < MUM_NUM_SUBKEYS - 1; i++)
    {
        for (int j = i + 1; j < MUM_NUM_SUBKEYS; j++)
        {
            if (!testEntropySubkeyPair(engine, i, j))
                return false;
        }
    }

    printf("SUCCESS testSubkeyEntropy, engine %s\n", engineType);

    return true;
}

bool testSimpleBlocks(void *engine, char *engineType)
{
    EMumError error;
    uint8_t plaintext[4096];
    uint8_t random[4096];
    uint8_t encrypt[4096];
    uint8_t decrypt[4096];
    uint32_t length, i;

    uint32_t encryptedBlockSize, plaintextBlockSize;
    error = MumPlaintextBlockSize(engine, &plaintextBlockSize);
    error = MumEncryptedBlockSize(engine, &encryptedBlockSize);

    fillRandomly(plaintext, plaintextBlockSize);

    uint32_t seqOut = 0;
    uint32_t seqIn = 0;

    error = MumEncryptBlock(engine, plaintext, encrypt, plaintextBlockSize, seqOut++);
    while (error == MUM_ERROR_BUFFER_WAIT_ENCRYPT)
        error = MumEncryptBlock(engine, random, encrypt, plaintextBlockSize, seqOut++);
    if (error != MUM_ERROR_OK)
        return false;

    error = MumDecryptBlock(engine, encrypt, decrypt, &length, &seqIn);
    while (error == MUM_ERROR_BUFFER_WAIT_DECRYPT)
        error = MumDecryptBlock(engine, random, decrypt, &length, &seqIn);
    if (error != MUM_ERROR_OK)
        return false;

    for (i = 0; i < plaintextBlockSize; i++)
    {
        if (plaintext[i] != decrypt[i])
        {
            printf("FAILED testSimpleBlocks, engine %s, block size %d\n",
                engineType, encryptedBlockSize);
            return false;
        }
    }
    printf("SUCCESS testSimpleBlocks, engine %s, block size %d\n",
        engineType, encryptedBlockSize);
    return true;
}

bool testUnitializedEngine(void *engine, char *engineType)
{
    EMumError error;
    uint8_t plaintext[4096];
    uint8_t encrypt[4096];
    uint8_t decrypt[4096];
    uint32_t length;

    uint32_t encryptedBlockSize, plaintextBlockSize;
    error = MumPlaintextBlockSize(engine, &plaintextBlockSize);
    error = MumEncryptedBlockSize(engine, &encryptedBlockSize);

    fillRandomly(plaintext, plaintextBlockSize);

    uint32_t seqOut = 0;
    uint32_t seqIn = 0;

    error = MumEncryptBlock(engine, plaintext, encrypt, plaintextBlockSize, seqOut++);
    if (error != MUM_ERROR_KEY_NOT_INITIALIZED)
        return false;

    error = MumDecryptBlock(engine, encrypt, decrypt, &length, &seqIn);
    if (error != MUM_ERROR_KEY_NOT_INITIALIZED)
        return false;


    uint32_t encrypted = 0;
    error = MumEncrypt(engine, plaintext, encrypt, plaintextBlockSize, &encrypted, 0);
    if (error != MUM_ERROR_KEY_NOT_INITIALIZED)
        return false;

    uint32_t decrypted = 0;
    error = MumDecrypt(engine, encrypt, decrypt, encrypted, &decrypted);
    if (error != MUM_ERROR_KEY_NOT_INITIALIZED)
        return false;


    printf("SUCCESS testUnitializedEngine, engine %s\n", engineType);
    return true;
}

bool testRandomlySizedBlocks(void *engine, char *engineType, EMumPaddingType paddingType)
{
    EMumError error;

    uint32_t encryptedBlockSize, plaintextBlockSize;
    error = MumPlaintextBlockSize(engine, &plaintextBlockSize);
    error = MumEncryptedBlockSize(engine, &encryptedBlockSize);

    uint8_t *plaintext = new uint8_t[1024*1024+4096];
    uint8_t *encrypt = new uint8_t[1280 * 1024];
    uint8_t *decrypt = new uint8_t[1024 * 1024 + 4096];
    for (int test = 0; test < 64; test++)
    {
        // Pick random number between 1 and 1048576
        uint32_t plaintextSize = (rand() & 0x000fffff) + 1;

        // Alternate between random fill and 32-bit int sequential fill
        if (test & 1)
            fillRandomly(plaintext, plaintextSize);
        else
            fillSequentially(plaintext, plaintextSize);

        uint32_t encrypted = 0;
        error = MumEncrypt(engine, plaintext, encrypt, plaintextSize, &encrypted, 0);
        if (error != MUM_ERROR_OK)
            return false;

        uint32_t decrypted = 0;
        error = MumDecrypt(engine, encrypt, decrypt, encrypted, &decrypted);
        if (error != MUM_ERROR_OK)
            return false;
        if (paddingType == MUM_PADDING_TYPE_ON && plaintextSize != decrypted)
            return false;

        for (uint32_t i = 0; i < plaintextSize; i++)
        {
            if (plaintext[i] != decrypt[i])
            {
                printf("FAILED testRandomlySizedBlocks, engine %s, plaintextSize %d\n",
                    engineType, plaintextSize);
                return false;
            }
        }
    }
    printf("SUCCESS testRandomlySizedBlocks, engine %s, block size  %d\n",
        engineType, encryptedBlockSize);
    delete[] plaintext;
    delete[] encrypt;
    delete[] decrypt;
    return true;
}

bool profileLargeBlocks(void *engine, char *engineType)
{
	EMumError error;
	uint32_t i;
	uint32_t plaintextSize = 256000000;
	uint32_t encryptBufferSize = plaintextSize*5/4;

    uint32_t encryptedBlockSize, plaintextBlockSize;
    error = MumPlaintextBlockSize(engine, &plaintextBlockSize);
    error = MumEncryptedBlockSize(engine, &encryptedBlockSize);
    
    //uint8_t *plaintext = new uint8_t[plaintextSize];
	//uint8_t *encrypt = new uint8_t[encryptBufferSize];
	//uint8_t *decrypt = new uint8_t[plaintextSize + encryptedBlockSize];

	fillSequentially(largePlaintext, plaintextSize);
	memset(largeEncrypt, 7, encryptBufferSize);
	memset(largeDecrypt, 9, plaintextSize + encryptedBlockSize);

    uint32_t encrypted = 0;
    startCounter();
    error = MumEncrypt(engine, largePlaintext, largeEncrypt, plaintextSize, &encrypted, 0);
    if (error != MUM_ERROR_OK)
		return false;
    double encryptTime = getCounter();

    uint32_t decrypted = 0;
    uint32_t predicted;
    MumEncryptedSize(engine, plaintextSize, &predicted);
    startCounter();
    error = MumDecrypt(engine, largeEncrypt, largeDecrypt, predicted, &decrypted);
    if (error != MUM_ERROR_OK)
        return false;
    double decryptTime = getCounter();

    float mb = (float)(plaintextSize) / 1000000.0f;
    printf("profileLargeBlocks: engine %s, encrypt size %d, total bytes %d\n",
        engineType, plaintextBlockSize, plaintextSize);
    printf("   encrypt time %f ms, MB/sec %f \n", encryptTime, mb / (encryptTime / 1000.0));
    printf("   decrypt time %f ms, MB/sec %f\n\n", decryptTime, mb / (decryptTime / 1000.0));

    for (i = 0; i < plaintextSize; i++)
    {
        if (largePlaintext[i] != largeDecrypt[i])
        {
            printf("FAILED profileLargeBlocks, engine %s, plaintextSize %d, decrypted %d, index %d\n",
                engineType, plaintextSize, decrypted, i);
            return false;
        }
    }

	return true;
}

bool doTest(void *engine, char *engineType, EMumPaddingType paddingType, EMumBlockType blockType)
{
    uint8_t clavier[MUM_KEY_SIZE];
    EMumError error;

    if (!testUnitializedEngine(engine, engineType))
        return false;

    fillRandomly(clavier, MUM_KEY_SIZE);
    error = MumInitKey(engine, clavier);
    if (!testSimpleBlocks(engine, engineType))
        return false;
    if (!testRandomlySizedBlocks(engine, engineType, paddingType))
        return false;
    if (!testEntropy(engine, engineType, paddingType))
        return false;
    if (!testSubkeyEntropy(engine, engineType, paddingType))
        return false;
    if (!testFileEncrypt(engine, engineType))
        return false;
    if (paddingType == MUM_PADDING_TYPE_ON && !testReferenceFileDecrypt(engine, engineType, blockType))
        return false;
    return true;
}


bool doProfiling(void *engine, char *engineType, bool withPadding)
{
	uint8_t clavier[MUM_KEY_SIZE];
	EMumError error;

    fillRandomly(clavier, MUM_KEY_SIZE);
	error = MumInitKey(engine, clavier);
    if (!profileLargeBlocks(engine, engineType))
        return false;
    return true;
}


bool multiTest(void *engine1, void *engine2)
{
    EMumError error;
    uint32_t decryptSize;
    uint32_t encryptSize;
    uint32_t outlength;


    uint32_t encryptedBlockSize, plaintextBlockSize;
    error = MumPlaintextBlockSize(engine1, &plaintextBlockSize);
    error = MumEncryptedBlockSize(engine1, &encryptedBlockSize);

    decryptSize = 28657;
    error = MumEncryptedSize(engine1, decryptSize, &encryptSize);
    if (error != MUM_ERROR_OK)
        return false;

    uint8_t *src = new uint8_t[decryptSize];
    uint8_t *dec1 = new uint8_t[decryptSize+ plaintextBlockSize];
    uint8_t *dec2 = new uint8_t[decryptSize+ plaintextBlockSize];
    uint8_t *enc1 = new uint8_t[encryptSize];
    uint8_t *enc2 = new uint8_t[encryptSize];
    for (uint32_t i = 0; i < decryptSize; i++)
        src[i] = (uint8_t)i;

    error = MumEncrypt(engine1, src, enc1, decryptSize, &outlength, 0);
    if (error != MUM_ERROR_OK)
        return false;
    if (outlength != encryptSize)
        return false;

    error = MumEncrypt(engine2, src, enc2, decryptSize, &outlength, 0);
    if (error != MUM_ERROR_OK)
        return false;
    if (outlength != encryptSize)
        return false;

    memset(dec1, 0, encryptSize);
    error = MumDecrypt(engine1, enc1, dec1, encryptSize, &outlength);
    if (error != MUM_ERROR_OK)
        return false;
    if (outlength != decryptSize)
        return false;

    memset(dec2, 0, encryptSize);
    error = MumDecrypt(engine2, enc2, dec2, encryptSize, &outlength);
    if (error != MUM_ERROR_OK)
        return false;
    if (outlength != decryptSize)
        return false;

    if (memcmp(src, dec1, decryptSize) != 0)
    {
        printf("FAILED multiTest!\n");
        return false;
    }
    if (memcmp(src, dec2, decryptSize) != 0)
    {
        printf("FAILED multiTest!\n");
        return false;
    }

    printf("SUCCESS multiTest!\n");
    return true;
}


bool doMultiEngineTest(EMumEngineType engineType1, EMumEngineType engineType2,
    EMumBlockType blockType, char *testString)
{
    uint8_t clavier[MUM_KEY_SIZE];
    EMumError error;

    fillRandomly(clavier, MUM_KEY_SIZE);

    void * engine1 = MumCreateEngine(MUM_ENGINE_TYPE_CPU, blockType, MUM_PADDING_TYPE_ON, 0);
    error = MumInitKey(engine1, clavier);

    void * engine2 = MumCreateEngine(MUM_ENGINE_TYPE_GPU_A, blockType, MUM_PADDING_TYPE_ON, 0);
    error = MumInitKey(engine2, clavier);

    if (!multiTest(engine1, engine2))
        return false;

    uint32_t encryptedBlockSize;
    error = MumEncryptedBlockSize(engine1, &encryptedBlockSize);
    printf("SUCCESS doMultiEngineTest, engine %s, block size %d\n",
        testString, encryptedBlockSize);

    MumDestroyEngine(engine1);
    MumDestroyEngine(engine2);
    return true;
}


bool doTests()
{
	for (int paddingIndex = 0; paddingIndex < TEST_NUM_PADDING_TYPES; paddingIndex++)
    {
        for (int engineIndex = 0; engineIndex < TEST_NUM_ENGINES; engineIndex++)
        {
            for (int blockType = firstTestBlockTypeList[engineIndex]; blockType <= MUM_BLOCKTYPE_4096; blockType++)
            {
                void * engine = MumCreateEngine(engineList[engineIndex], (EMumBlockType)blockType, paddingList[paddingIndex], TEST_MUM_NUM_THREADS);
                char testName[128];
                sprintf_s(testName, "%s:%s", engineName[engineIndex], paddingName[paddingIndex]);
                if (!doTest(engine, testName, paddingList[paddingIndex], (EMumBlockType)blockType))
                    return false;
                MumDestroyEngine(engine);
                engine = NULL;
            }
        }
    }
	return true;
}

#ifdef CREATE_REFERENCE_FILES
bool createReferenceFilesFromEngine(void * engine, EMumBlockType blockType)
{
    EMumError error;

    for (int i = 0; i < NUM_REFERENCE_FILES; i++)
    {
        char encryptedname[512];
        error = MumCreateEncryptedFileName(blockType, referenceFiles[i], encryptedname, 512);
        if (error != MUM_ERROR_OK)
            return false;
        error = MumEncryptFile(engine, referenceFiles[i], encryptedname);
        if (error != MUM_ERROR_OK)
            return false;
    }
    return true;
}



bool createReferenceFiles()
{
    char *referenceFileKey = "..\\referencefiles\\key.bin";

    // create key
    uint8_t clavier[MUM_KEY_SIZE];
    srand(610);
    fillRandomly(clavier, MUM_KEY_SIZE);

    // write it to disk
    FILE *f;
    size_t res;
    fopen_s(&f, referenceFileKey, "wb");
    if (!f) return false;
    res = fwrite(clavier, 1, MUM_KEY_SIZE, f);
    fclose(f);
    if (res != MUM_KEY_SIZE)
        return false;

    for (int blockType = MUM_BLOCKTYPE_128; blockType <= MUM_BLOCKTYPE_4096; blockType++)
    {
        void * engine = MumCreateEngine(MUM_ENGINE_TYPE_CPU, (EMumBlockType)blockType, MUM_PADDING_TYPE_ON, TEST_MUM_NUM_THREADS);
        EMumError error = MumLoadKey(engine, referenceFileKey);
        if (error != MUM_ERROR_OK)
            return false;
        if (!createReferenceFilesFromEngine(engine, (EMumBlockType)blockType))
            return false;
        MumDestroyEngine(engine);
        engine = NULL;
    }
    return true;
}
#endif

bool doProfilings()
{
    printf("\n");
    for (int engineIndex = 0; engineIndex < TEST_NUM_ENGINES; engineIndex++)
    {
        for (int paddingIndex = 0; paddingIndex < TEST_NUM_PADDING_TYPES; paddingIndex++)
        {
            for (int blockType = firstProfilingBlockTypeList[engineIndex]; blockType <= MUM_BLOCKTYPE_4096; blockType++)
            {
                for (int i = 0; i < 1; i++)
                {
                    void * engine = MumCreateEngine(engineList[engineIndex], (EMumBlockType)blockType, paddingList[paddingIndex], TEST_MUM_NUM_THREADS);
                    char testName[128];
                    sprintf_s(testName, "%s:%s", engineName[engineIndex], paddingName[paddingIndex]);
                    if (!doProfiling(engine, testName, (paddingIndex == 1)))
                        return false;
                    MumDestroyEngine(engine);
                    engine = NULL;
                }
            }
        }
    }
    return true;
}

bool doMultiEngineTests()
{
    for (int blockType = MUM_BLOCKTYPE_128; blockType <= MUM_BLOCKTYPE_4096; blockType++)
    {
        if (!doMultiEngineTest(
			MUM_ENGINE_TYPE_CPU,
			MUM_ENGINE_TYPE_GPU_A,
            (EMumBlockType)blockType,
            "CPU + GPUA"))
            return false;
    }

    if (!doMultiEngineTest(
		MUM_ENGINE_TYPE_CPU,
		MUM_ENGINE_TYPE_GPU_B,
        MUM_BLOCKTYPE_4096,
        "CPU + GPUB"))
        return false;

    return true;
}


int main(int argc, char* argv[])
{
    int result = 0;
#ifdef CREATE_REFERENCE_FILES
    if (createReferenceFiles())
        return -1;
#endif

    init();

    srand(GetTickCount());

    if (!loadUrFiles())
        result = -1;
	
	if (!doTests() )
        result = -1;

    if (!doProfilings())
        result = -1;

    // if ( !doMultiEngineTests() )
    // return -1;

    if (result != -1)
        printf_s("Success!!! Done!!!\n");
    else
        printf_s("Done...but we failed someplace.\n");

    while (true)
        ;
    return result;
}


