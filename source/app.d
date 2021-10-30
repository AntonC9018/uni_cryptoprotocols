import std.digest;
import std.digest.sha;
import std.range;
import std.string;
import std.algorithm;
import common.util;


auto calculateHMAC(alias hashFunction, int blockSize)(const(ubyte)[] key, const(ubyte)[] message)
{
    // The hash function returns a static array so it needs to be 
    // stack allocated outside the if scope.
    typeof(hashFunction(key)) hashTemporary = void;

    if (key.length > blockSize)
    {
        hashTemporary = hashFunction(key);
        key = hashTemporary[];
    }
    key.length = blockSize;
    
    ubyte[blockSize] outerPad = void;
    outerPad[] = key[] ^ 0x5c;
    ubyte[blockSize] innerPad = void;
    innerPad[] = key[] ^ 0x36;

    return hashFunction(outerPad ~ hashFunction(innerPad ~ message));
}
unittest
{
    auto key = representation("key");
    auto message = representation("The quick brown fox jumps over the lazy dog");
    auto hmac = calculateHMAC!(sha256Of, 64)(key, message);
    assert(hmac.toHexString!(LetterCase.lower) == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

struct KeyCMAC(int blockSize)
{
    ubyte[blockSize] k1;
    ubyte[blockSize] k2;
}

template BlockSize(alias blockCipher)
{
    static if (is(typeof(&blockCipher) : ubyte[blockSize] delegate(in ubyte[blockSize]), int blockSize))
    {
        enum BlockSize = blockSize;
    }
    else static assert(0, "`blockCipher` is not a block cipher");
}

template CMAC(alias blockCipher)
{
    enum blockSize = BlockSize!blockCipher;

    auto getKey()
    {
        static if (blockSize == 8)
            enum ubyte c = 0x1b;
        else static if (blockSize == 16)
            enum ubyte c = 0x87;
        else static assert(0, "The size of the block cipher must be 8 or 16");

        ubyte[blockSize] zeros = 0;
        auto k0 = blockCipher(zeros);

        ubyte[blockSize] k1 = void;
        shiftLeftInto(k0[], k1[]);
        if (k0[0] & 0x80)
            k1[15] ^= c;

        ubyte[blockSize] k2 = void;
        shiftLeftInto(k1[], k2[]);
        if (k1[0] & 0x80)
            k2[15] ^= c;

        return KeyCMAC!blockSize(k1, k2);
    }

    auto getTag(ref const(KeyCMAC!blockSize) key, const(ubyte)[] message)
    {
        ubyte[blockSize] mLast = void;
        auto numIters = message.length / blockSize;

        // complete block
        if (message.length && message.length % blockSize == 0)
        {
            mLast[] = key.k1[] ^ message[($ - blockSize) .. $];
            numIters--;
        }
        // incomplete block
        else
        {
            auto byteCount = message.length % blockSize;
            mLast[0..byteCount]         = key.k2[0..byteCount] ^ message[($ - byteCount) .. $];
            mLast[byteCount]            = key.k2[byteCount] ^ 0x80;
            mLast[(byteCount + 1) .. $] = key.k2[(byteCount + 1) .. $];
        }
        
        size_t messageIndex = 0;
        ubyte[blockSize] x = 0;

        foreach (i; 0..numIters)
        {
            x[] ^= message[messageIndex .. (messageIndex + blockSize)];
            x = blockCipher(x);
            messageIndex += blockSize;
        }

        x[] ^= mLast[];
        return blockCipher(x);
    }
}
unittest
{
    import aes;

    // Test vectors: https://datatracker.ietf.org/doc/html/rfc4493#section-4
    enum keyBitSize = 128;
    ubyte[keyBitSize/8] key = void;
    fromHexString(key[], "2b7e151628aed2a6abf7158809cf4f3c");

    AESContext ctx = createEncryptionContext(key[]); 

    enum inputSize = 16;
    auto doAes(in ubyte[inputSize] input) { return ctx.cryptEcb(false, input); }

    ubyte[inputSize] zeros = 0;
    assert(doAes(zeros).toHexString!(LetterCase.lower) == "7df76b0c1ab899b33e42f047b91b546f");

    alias AesCMAC = CMAC!doAes;
    auto processedKey = AesCMAC.getKey();
    assert(processedKey.k1.toHexString!(LetterCase.lower) == "fbeed618357133667c85e08f7236a8de");
    assert(processedKey.k2.toHexString!(LetterCase.lower) == "f7ddac306ae266ccf90bc11ee46d513b");

    ubyte[inputSize] tag;
    
    tag = AesCMAC.getTag(processedKey, []);
    assert(equal(tag[], fromHexString("bb1d6929e95937287fa37d129b756746")));

    tag = AesCMAC.getTag(processedKey, fromHexString("6bc1bee22e409f96e93d7e117393172a").array);
    assert(equal(tag[], fromHexString("070a16b46b4d4144f79bdd9dd04a287c")));

    tag = AesCMAC.getTag(processedKey, 
        fromHexString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411").array);
    assert(equal(tag[], fromHexString("dfa66747de9ae63030ca32611497c827")));
}


void shiftLeftInto(ubyte[] arrSource, ubyte[] arrDest)
{
    ubyte leftover = 0;
    auto len = arrSource.length;
    foreach (i; iota(len).retro)
    {
        arrDest[i] = cast(ubyte)((arrSource[i] << 1) | leftover);
        leftover = (arrSource[i] & 0x80) >> 7; 
    }
}
unittest
{
    ubyte[4] source = [0x00, 0x81, 0x88, 0x80];
    ubyte[4] dest = void;
    shiftLeftInto(source[], dest[]);
    assert(dest[] == [0x01, 0x03, 0x11, 0x00]);
}


int endianSwap(int a)
{
    return ((a >> 24) & 0x000000ff) 
        | ((a >> 8) & 0x0000ff00)
        | ((a << 8) & 0x00ff0000)
        | ((a << 24) & 0xff000000); 
}
unittest
{
    assert(endianSwap(0x00000080) == int.min);
    assert(endianSwap(0x12345678) == 0x78563412);
}




// struct UMAC(size_t aesBlockSize, size_t aesKeyLength)
// {
//     ubyte[aesKeyLength] 
// }




template UMAC(size_t aesBlockLength, size_t aesKeyLength, size_t umacKeyLength = 8)
{
    import aes;

    void getKey(ubyte[] outBuffer, in AESContext encryptionContext, byte streamIndex)
    {
        ubyte[aesBlockLength] inBuffer = 0;

        // Setup the initial value
        inBuffer[$ - 9] = streamIndex;
        inBuffer[$ - 1] = 1;

        while (outBuffer.length >= aesBlockLength) 
        {
            outBuffer[0..aesBlockLength] = encryptEcb(encryptionContext, inBuffer);
            outBuffer = outBuffer[aesBlockLength..$];
            inBuffer[$ - 1]++;
        }
        if (outBuffer.length > 0) 
            outBuffer[] = encryptEcb(encryptionContext, inBuffer)[0..outBuffer.length];
    }

    struct PadDerivationContext
    {
        ubyte[aesBlockLength] previousAesOutput;
        ubyte[aesBlockLength] nonce;
        ubyte[aesKeyLength] pseudoradomKey;
    }

    PadDerivationContext padDerivationContextInit(in AESContext pseudorandomFunctionAesContext)
    {
        ubyte[umacKeyLength] buffer;
        getKey(buffer[], pseudorandomFunctionAesContext, 0);
        aes.createEncryptionContext(buffer[]);
    }
}


void main()
{
    import aes;
    import std.stdio;

    enum keyBitSize = 128;
    enum inputSize = 16;

    ubyte[keyBitSize/8] key = void;
    AESContext ctx = createEncryptionContext(key);

    auto doAes(in ubyte[inputSize] input)
    {
        return ctx.cryptEcb(false, input);
    }

    // alias AesUMAC = UMAC!doAes;
    // ubyte[16] processedKey = void;
    // AesUMAC.getKey(processedKey[], 0);
    // writeln(processedKey);
}