//////////////////////////////////////////////////////////////////////////
//                                                                      //
//   Mumblepad Block Cipher                                             //
//   Version 1, completed March 14, 2017                                //
//                                                                      //
//   Key size 4096 bytes, 32768 bits                                    //
//   Six different block sizes: 128, 256, 512, 1024, 2048, 4096 bytes   //
//   Encryption and decryption, runs on either CPU and GPU              //
//   May run multi-threaded on CPU.                                     //
//   Runs on GPU with OpenGL or OpenGL ES 2.0                           //
//                                                                      //
//   Encrypted blocks containing same plaintext are different, due to   //
//   small amount of per-block random number padding.                   //
//   Encrypted block contains length, 16-bit sequence number, 32-bit    //
//   checksum.                                                          //
//   No block cipher mode required                                      //
//   Can use parallel processing, multi-threaded encrypt/decrypt        //
//                                                                      //
//   8 rounds, 2 passes per round                                       //
//   Encrypt: diffusion pass followed by confusion pass.                //
//   Decrypt: inverse confusion followed by inverse diffusion.          //
//                                                                      //
//   Free for non-commercial use, analysis/evaluation.                  //
//                                                                      //
//   Copyright 2017, Kyle Granger                                       //
//   Email contact:  kyle.granger@chello.at                             //
//                                                                      //
//////////////////////////////////////////////////////////////////////////



#include <assert.h>
#include <string.h>
#include "stdio.h"
#include "stdlib.h"
#include "mumengine.h"
#include "mumblepad.h"
#include "mumblepadmt.h"
#ifdef USE_MUM_OPENGL
#include "mumblepadgla.h"
#include "mumblepadglb.h"
#include "mumblepadglc.h"
#endif

// There are 563 prime numbers between 3 and 4093, inclusive
// This is a random selection of 256 of them, all unique
static uint32_t primeNumberTable[256] = {
    2609, 3571, 2287, 3167,  499, 1087,   43, 2293,
    2213, 1049, 3169,  907,  223, 2633, 1213, 2441,
     937, 1327,  281, 3257,  311, 1019,  887, 4091,
    2999, 2143, 1823, 1867, 3259, 1543, 1201,  101,
    1933, 1297, 1231, 3617, 1097, 1723,  947,  859,
    2069, 4027, 1847,  487,  167, 3271, 3413, 2657,
    1279,  283,   67, 2063, 3209,  787, 1609, 3833,
    1259, 2137, 2687,  131, 1051, 2273, 1801, 3691,
     911,  701, 1889, 1733, 1307, 1831, 1451,  307,
    2917, 2207, 3527,  653, 2087,   83, 1471, 3847,
     683, 3491,  401, 3533,  463, 1753, 2153, 1973,
      73,   47, 2621, 3851, 3917, 1427,   17, 1171,
    1277,   19, 1301, 1009, 1061,    7, 2957, 2903,
    1627, 2683, 3943,  373, 2819,   13,  733, 1193,
    3677, 2347, 2389,  853, 2707, 2351,  571, 3559,
     757,  631,  199, 1069,  523, 3823, 4007, 2753,
    2437, 1031, 1289, 1249, 3803,  257, 3797,   89,
    1153, 3673, 2593, 3767, 2203, 1091,  137, 3181,
     227,  467, 2557,  163, 3449, 1361, 2311, 1373,
    2711, 2477, 1291, 2677, 2393,  643, 3727, 3631,
    2521, 3407, 2663, 1481, 2053, 3343,  613, 2333,
    3607, 2749, 1553,  431, 2099,  191, 2719, 3931,
     971, 2179,   41, 2713, 1531, 3049, 4001, 2693,
     857,   61, 4003, 4051,  691, 3881,  443, 3221,
     521, 1129, 3929, 1931, 2971, 2269, 3217,  149,
    4049, 1697, 2221,  719, 1747,  811,  127, 2341,
     677, 3011, 2381, 2417, 2003, 1601,  509,  773,
     211, 1993, 2729,  233, 1223, 2791, 1409,  241,
    1483, 3709, 1777, 3779, 2371, 3761,    3, 3301,
    3121,  709, 1997,   37, 3907, 3137, 3313, 4057,
    2447, 1523,  673, 4093, 2399,  797,  251,  593,
    2083, 3613,  109, 1871, 1811, 3469, 1787, 2777
};


#ifdef USE_MUM_OPENGL
CMumGlWrapper *CMumEngine::mMumGlWrapper = NULL;
#endif


CMumEngine::CMumEngine(EMumEngineType engineType, EMumBlockType blockType, EMumPaddingType paddingType, uint32_t numThreads)
{
    mMumInfo.engineType = engineType;
    mMumInfo.paddingOn = (paddingType == MUM_PADDING_TYPE_ON);
    mMumInfo.blockType = blockType;
    mMumInfo.keyInitialized = false;

    mMumInfo.numRoundsPerBlock = 8;
#ifdef USE_MUM_OPENGL
    if (engineType >= MUM_ENGINE_TYPE_GPU_B)
        mMumInfo.numRoundsPerBlock = 1;
#endif

    InitXorTextureData();

#ifdef USE_MUM_OPENGL
    if ( engineType >= MUM_ENGINE_TYPE_GPU_A )
    {
        if ( mMumGlWrapper == NULL )
        {
            mMumGlWrapper = new CMumGlWrapper();
            mMumGlWrapper->Init();
        }
    }
#endif
    switch ( mMumInfo.engineType )
    {
    case MUM_ENGINE_TYPE_CPU:
        mMumRenderer = new CMumblepad(&mMumInfo);
        break;
    case MUM_ENGINE_TYPE_CPU_MT:
        mMumRenderer = new CMumblepadMt(&mMumInfo, numThreads);
        break;
#ifdef USE_MUM_OPENGL
    case MUM_ENGINE_TYPE_GPU_A:
        mMumRenderer = new CMumblepadGla(&mMumInfo, mMumGlWrapper);
        break;
    case MUM_ENGINE_TYPE_GPU_B:
        mMumRenderer = new CMumblepadGlb(&mMumInfo, mMumGlWrapper);
        break;
#endif
    default:
        assert(0);
    }

}

CMumEngine::~CMumEngine()
{
    delete mMumRenderer;
}

uint32_t CMumEngine::PlaintextBlockSize()
{
    return mMumInfo.plaintextBlockSize;
}

uint32_t CMumEngine::EncryptedBlockSize()
{
    return mMumInfo.encryptedBlockSize;
}

uint32_t CMumEngine::EncryptedSize(uint32_t plaintextSize)
{
    uint32_t encryptedOutputSize = ((plaintextSize + mMumInfo.plaintextBlockSize - 1) / mMumInfo.plaintextBlockSize) * mMumInfo.encryptedBlockSize;
    return encryptedOutputSize;
}


EMumError CMumEngine::EncryptFile(char *srcfile, char *dstfile)
{
    EMumError error;
    FILE *infile, *outfile;
    size_t res;
    uint8_t inbuffer[MUM_MAX_BLOCK_SIZE];
    uint8_t outbuffer[MUM_MAX_BLOCK_SIZE];
    uint32_t remaining;
    uint32_t readsize;
    uint32_t seqnum = 0;

    if (!mMumInfo.keyInitialized)
        return MUM_ERROR_KEY_NOT_INITIALIZED;

    mMumRenderer->ResetEncryption();

    fopen_s(&infile,srcfile,"rb");
    if ( !infile )
        return MUM_ERROR_FILEIO_INPUT;

    fseek(infile,0,SEEK_END);
    remaining = ftell(infile);
    fseek(infile,0,SEEK_SET);

    fopen_s(&outfile,dstfile,"wb");
    if ( !outfile )
    {
        fclose(infile);
        return MUM_ERROR_FILEIO_OUTPUT;
    }

    uint32_t latency = 0;
    while ( remaining > 0 )
    {
        // set read size
        if ( remaining > mMumInfo.plaintextBlockSize)
            readsize = mMumInfo.plaintextBlockSize;
        else readsize = remaining;
        remaining -= readsize;

        // read in from source
        res = fread(inbuffer,1,readsize,infile);
        if ( res != readsize )
        {
            fclose(infile);
            fclose(outfile);
            return MUM_ERROR_FILEIO_INPUT;
        }

        // do encrypt
        EMumError error = MUM_ERROR_OK;
        error = EncryptBlock(inbuffer, outbuffer, readsize, seqnum++);
        if ( error == MUM_ERROR_BUFFER_WAIT_ENCRYPT)
             latency++;
        else if (error != MUM_ERROR_OK)
        {
            fclose(infile);
            fclose(outfile);
            return error;
        }
        else
        {
            // write to destination
            res = fwrite(outbuffer,1,mMumInfo.encryptedBlockSize,outfile);
            if ( res != mMumInfo.encryptedBlockSize)
            {
                fclose(infile);
                fclose(outfile);
                return MUM_ERROR_FILEIO_OUTPUT;
            }
        }
    }
    while (latency > 0)
    {
        uint8_t dummy[MUM_MAX_BLOCK_SIZE];
        error = EncryptBlock(dummy, outbuffer, mMumInfo.plaintextBlockSize, seqnum++);
        if ( error == MUM_ERROR_BUFFER_WAIT_ENCRYPT)
            continue;
        if (error != MUM_ERROR_OK)
        {
            fclose(infile);
            fclose(outfile);
            return error;
        }
        res = fwrite(outbuffer,1,mMumInfo.encryptedBlockSize,outfile);
        if ( res != mMumInfo.encryptedBlockSize)
        {
            fclose(infile);
            fclose(outfile);
            return MUM_ERROR_FILEIO_OUTPUT;
        }
        latency--;
    }

    fclose(infile);
    fclose(outfile);
    return MUM_ERROR_OK;
}


EMumError CMumEngine::DecryptFile(char *srcfile, char *dstfile)
{
    EMumError error;
    FILE *infile, *outfile;
    size_t res;
    uint8_t inbuffer[MUM_MAX_BLOCK_SIZE];
    uint8_t outbuffer[MUM_MAX_BLOCK_SIZE];
    uint32_t remaining;
    uint32_t decryptSize, seqnum;
    uint8_t firstBlock[MUM_MAX_BLOCK_SIZE];

    if (!mMumInfo.keyInitialized)
        return MUM_ERROR_KEY_NOT_INITIALIZED;

    mMumRenderer->ResetDecryption();

    fopen_s(&infile,srcfile,"rb");
    if ( !infile )
        return MUM_ERROR_FILEIO_INPUT;

    fseek(infile,0,SEEK_END);
    remaining = ftell(infile);
    fseek(infile,0,SEEK_SET);

    fopen_s(&outfile,dstfile,"wb");
    if ( !outfile )
    {
        fclose(infile);
        return MUM_ERROR_FILEIO_OUTPUT;
    }

    uint32_t latency = 0;
    bool firstTime = false;
    while ( remaining > 0 )
    {
        // read in from source
        res = fread(inbuffer, 1, mMumInfo.encryptedBlockSize, infile);
        if ( res != mMumInfo.encryptedBlockSize)
        {
            assert(0);
            fclose(infile);
            fclose(outfile);
            return MUM_ERROR_FILEIO_INPUT;
        }
        remaining -= mMumInfo.encryptedBlockSize;
        if ( firstTime )
        {
            firstTime = false;
            memcpy(firstBlock, inbuffer, mMumInfo.encryptedBlockSize);
        }

        // do encrypt
        error = DecryptBlock(inbuffer, outbuffer, &decryptSize, &seqnum);
        if ( error == MUM_ERROR_BUFFER_WAIT_DECRYPT)
             latency++;
        else if ( error != MUM_ERROR_OK)
            return error;
        else
        {
            // write to destination
            res = fwrite(outbuffer,1,decryptSize,outfile);
            if ( res != decryptSize )
            {
                assert(0);
                fclose(infile);
                fclose(outfile);
                return MUM_ERROR_FILEIO_OUTPUT;
            }
        }
    }

    while (latency > 0)
    {
        error = DecryptBlock(firstBlock, outbuffer, &decryptSize, &seqnum);
        if ( error == MUM_ERROR_BUFFER_WAIT_ENCRYPT)
            continue;
        if ( error != MUM_ERROR_OK)
            return error;

        // write to destination
        res = fwrite(outbuffer,1,decryptSize,outfile);
        if ( res != decryptSize )
        {
            assert(0);
            fclose(infile);
            fclose(outfile);
            return MUM_ERROR_FILEIO_OUTPUT;
        }
        remaining -= mMumInfo.encryptedBlockSize;
        latency--;
    }
    fclose(infile);
    fclose(outfile);
    return MUM_ERROR_OK;
}


EMumError CMumEngine::Encrypt(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength, uint16_t seqNum)
{
    if (!mMumInfo.keyInitialized)
        return MUM_ERROR_KEY_NOT_INITIALIZED;
    mMumRenderer->ResetEncryption();
    return mMumRenderer->Encrypt(src, dst, length, outlength, seqNum);
}

EMumError CMumEngine::Decrypt(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t *outlength)
{
    if (!mMumInfo.keyInitialized)
        return MUM_ERROR_KEY_NOT_INITIALIZED;
    mMumRenderer->ResetDecryption();
    return mMumRenderer->Decrypt(src, dst, length, outlength);
}



// Return little-endian integer read from key at a specific offset. Depending on
// the offset, this may roll-around from the end of the subkey data to the start.
uint32_t CMumEngine::GetSubkeyInteger(uint8_t *subkey, uint32_t offset)
{
    uint32_t value = 0;
    for (uint32_t i = 0; i < 4; i++)
    {
        value <<= 8;
        value += subkey[(offset + (3-i)) & MUM_KEY_MASK];
    }
    return value;
}


void CMumEngine::InitXorTextureData()
{
    for (uint32_t row = 0; row < MUM_NUM_8BIT_VALUES; row++ )
    {
        for (uint32_t col = 0; col < MUM_NUM_8BIT_VALUES; col++ )
        {
            mMumInfo.xorTextureData[row*MUM_NUM_8BIT_VALUES+col] = (uint8_t)( row ^ col );
        }
    }
}


EMumError CMumEngine::EncryptBlock(uint8_t *src, uint8_t *dst, uint32_t length, uint32_t seqnum)
{
    if (!mMumInfo.keyInitialized)
        return MUM_ERROR_KEY_NOT_INITIALIZED;
    return mMumRenderer->EncryptBlock(src, dst, length, seqnum);
}

EMumError CMumEngine::DecryptBlock(uint8_t *src, uint8_t *dst, uint32_t *length, uint32_t *seqnum)
{
    if (!mMumInfo.keyInitialized)
        return MUM_ERROR_KEY_NOT_INITIALIZED;
    return mMumRenderer->DecryptBlock(src, dst, length, seqnum);
}

void CMumEngine::CreatePrimeCycleWithOffset(uint32_t primeIndex, uint32_t offset, uint8_t *outCycle)
{
    uint32_t prime = primeNumberTable[primeIndex&255];
    for (uint32_t i = 0; i < MUM_KEY_SIZE; i++)
    {
        outCycle[i] = mMumInfo.key[offset&MUM_KEY_MASK];
        offset += prime;
    }
}


void CMumEngine::CreatePermuteTable(uint8_t *subkey, uint32_t numEntries, uint32_t *outTable)
{
    uint32_t used[MUM_MAX_10BIT_VALUES];

    assert(numEntries <= MUM_MAX_10BIT_VALUES);
    memset(used, 0, numEntries*sizeof(uint32_t));
    memset(outTable, 0xff, numEntries*sizeof(uint32_t));

    uint32_t offset = 0;
    for (uint32_t n = 0; n < numEntries - 1; n++)
    {
        uint32_t s = GetSubkeyInteger(subkey, offset);
        offset += 4;

        uint32_t mod = numEntries - n;
        uint32_t index = s % mod;
        uint32_t m = 0;
        assert(index < numEntries);
        for (uint32_t p = 0; p < numEntries; p++)
        {
            if (used[p] == 0)
            {
                if (index == m)
                {
                    used[p] = 1;
                    outTable[n] = p;
                    break;
                }
                m++;
            }
        }
    }

    // handle last value
    for (uint32_t n = 0; n < numEntries; n++)
    {
        if (used[n] == 0)
        {
            outTable[numEntries - 1] = n;
            used[n] = 1;
        }
    }
    uint32_t total = 0;
    for (uint32_t n = 0; n < numEntries; n++)
    {
        total += outTable[n];
    }
    assert(total == numEntries*(numEntries - 1) / 2);
}


void CMumEngine::InitBitmasks()
{
    uint32_t row, col, index, mask,round;

    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        // now that we have our permuations, create the bitmasks themselves
        mMumInfo.bitmasks[round][0] = (1 << mMumInfo.permuteTables3bit[round][0]) + (1 << mMumInfo.permuteTables3bit[round][1]);
        mMumInfo.bitmasks[round][1] = (1 << mMumInfo.permuteTables3bit[round][2]) + (1 << mMumInfo.permuteTables3bit[round][3]);
        mMumInfo.bitmasks[round][2] = (1 << mMumInfo.permuteTables3bit[round][4]) + (1 << mMumInfo.permuteTables3bit[round][5]);
        mMumInfo.bitmasks[round][3] = (1 << mMumInfo.permuteTables3bit[round][6]) + (1 << mMumInfo.permuteTables3bit[round][7]);
        for ( row = 0; row < MUM_MASK_TABLE_ROWS; row++ )
        {
            index = row / 8;
            mask = mMumInfo.bitmasks[round][index];
            for ( col = 0; col < MUM_NUM_8BIT_VALUES; col++ )
            {
                mMumInfo.bitmaskTextureData[round][row*MUM_NUM_8BIT_VALUES+col] = (uint8_t)(col & mask);
            }
        }
    }
}



void CMumEngine::InitPositionTables()
{
    uint32_t n, round;
    uint32_t x, y, mapX, mapY;
    uint32_t position, value;
    uint32_t numRows = mMumInfo.numRows;

    uint32_t textureScalar = 4096/mMumInfo.plaintextBlockSize;
    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        for (n = 0; n < numRows*MUM_CELLS_X; n++)
        {
            x = n % MUM_CELLS_X;
            y = n / MUM_CELLS_X;
            for ( position = 0; position < MUM_NUM_POSITIONS; position++ )
            {
                //index = (n * primes[position]) % (numRows*MUM_CELLS_X);
                value = mMumInfo.permuteTables10bit[round][position][n];
                mapX = value % MUM_CELLS_X;
                mapY = value / MUM_CELLS_X;
                mMumInfo.positionTables5bitX[round][y][x][position] = mapX;
                mMumInfo.positionTables5bitY[round][y][x][position] = mapY;
                mMumInfo.positionTables5bitXI[round][mapY][mapX][position] = x;
                mMumInfo.positionTables5bitYI[round][mapY][mapX][position] = y;
                mMumInfo.positionTextureDataX[round][y][x][position] = (uint8_t)(mapX * 8 + 4);
                mMumInfo.positionTextureDataY[round][y][x][position] = (uint8_t)(mapY * 8 * textureScalar + 4 * textureScalar);
                mMumInfo.positionTextureDataYB[round][y][x][position] = (uint8_t)(mapY + round*numRows);
                mMumInfo.positionTextureDataXI[round][mapY][mapX][position] = (uint8_t)(x * 8 + 4);
                mMumInfo.positionTextureDataYI[round][mapY][mapX][position] = (uint8_t)(y * 8 * textureScalar+ 4 * textureScalar);
                mMumInfo.positionTextureDataYIB[round][mapY][mapX][position] = (uint8_t)(y + (7-round)*numRows);
            }
        }
    }
}


void CMumEngine::InitSubkeys()
{
    uint8_t cycles[MUM_NUM_CYCLES][MUM_KEY_SIZE];
    uint32_t offset = 0;
    uint32_t index = 0;
    for (uint32_t s = 0; s < MUM_NUM_SUBKEYS; s++)
    {
        uint8_t *pcycles[MUM_NUM_CYCLES];
        for (uint32_t i = 0; i < MUM_NUM_CYCLES; i++)
        {
            pcycles[i] = cycles[i];
            CreatePrimeCycleWithOffset(index, offset, pcycles[i]);
            index += MUM_CYCLE_INDEX_INCREMENT;
            offset += MUM_CYCLE_OFFSET_INCREMENT;
        }
        uint8_t *subkey = mMumInfo.subkeys[s];
        for (uint32_t i = 0; i < MUM_KEY_SIZE; i++)
        {
            uint8_t value = *pcycles[0]++;
            for (uint32_t i = 1; i < MUM_NUM_CYCLES; i++)
                value ^= *pcycles[i]++;
            *subkey++ = value;
        }
    }
}


void CMumEngine::InitPermuteTables()
{
    uint32_t round, y, n;
    uint32_t numRows = mMumInfo.numRows;
    // first eight subkeys used for confusion pass.
    uint32_t subkeyIndex = 8;

    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        CreatePermuteTable(mMumInfo.subkeys[subkeyIndex++], MUM_NUM_3BIT_VALUES, mMumInfo.permuteTables3bit[round]);
    }

    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        for ( y = 0; y < numRows; y++ )
        {
            CreatePermuteTable(mMumInfo.subkeys[subkeyIndex++], MUM_NUM_8BIT_VALUES, mMumInfo.permuteTables8bit[round][y]);
            for ( n = 0; n < MUM_NUM_8BIT_VALUES; n++ )
                mMumInfo.permuteTables8bitI[round][y][mMumInfo.permuteTables8bit[round][y][n]] = n;
            for ( n = 0; n < MUM_NUM_8BIT_VALUES; n++ )
            {
                mMumInfo.permuteTextureData[round][y][n] = (uint8_t)mMumInfo.permuteTables8bit[round][y][n];
                mMumInfo.permuteTextureDataI[round][y][n] = (uint8_t)mMumInfo.permuteTables8bitI[round][y][n];
            }
        }
    }

    for ( round = 0; round < MUM_NUM_ROUNDS; round++ )
    {
        for (uint32_t position = 0; position < MUN_NUM_POSITIONS; position++)
            CreatePermuteTable(mMumInfo.subkeys[subkeyIndex++], numRows*MUM_CELLS_X, mMumInfo.permuteTables10bit[round][position]);
    }
}


EMumError CMumEngine::InitKey(uint8_t *key)
{
    memcpy(mMumInfo.key, key, MUM_KEY_SIZE);
    InitSubkeys();
    InitPermuteTables();
    InitPositionTables();
    InitBitmasks();
    mMumRenderer->InitKey();
    mMumInfo.keyInitialized = true;
    return MUM_ERROR_OK;
}

EMumError CMumEngine::LoadKey(char *keyfile)
{
    FILE *f;
    fopen_s(&f, keyfile, "rb");
    if (!f)
        return MUM_ERROR_KEYFILE_READ;

    uint8_t key[MUM_KEY_SIZE];
    size_t res = fread(key, 1, MUM_KEY_SIZE, f);
    fclose(f);
    if (res != MUM_KEY_SIZE)
        return MUM_ERROR_KEYFILE_READ; 
    return InitKey(key);
}

EMumError CMumEngine::GetSubkey(uint32_t index, uint8_t *subkey)
{
    if (!mMumInfo.keyInitialized) 
        return MUM_ERROR_KEY_NOT_INITIALIZED;
    if (index >= MUM_NUM_SUBKEYS)
        return MUM_ERROR_SUBKEY_INDEX_OUTOFRANGE;
    memcpy(subkey, mMumInfo.subkeys[index],MUM_KEY_SIZE);
    return MUM_ERROR_OK;
}
