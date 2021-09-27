import std.digest;
import std.digest.sha;
import std.range;
import std.string;

void main()
{
    import aes;
    import std.algorithm.comparison;




    enum keyBitSize = 128;
    ubyte[keyBitSize/8] key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    aes_context ctx;
    aes_setkey_enc(&ctx, key.ptr, keyBitSize); 

    enum inputSize = 16;
    auto doAes(ref const(ubyte)[inputSize] input)
    {
        ubyte[inputSize] output;
        aes_crypt_ecb(&ctx, false, input.ptr, output.ptr);
        return output;
    }

    ubyte[inputSize] zeros = 0;
    import std.stdio;
    assert(doAes(zeros).toHexString!(LetterCase.lower) == "7df76b0c1ab899b33e42f047b91b546f");
    auto processedKey = getKeyCMAC!16(&doAes, key[]);
    writeln(processedKey.k1.toHexString!(LetterCase.lower));
    writeln(processedKey.k2.toHexString!(LetterCase.lower));
    auto tag = getTagCMAC!16(&doAes, processedKey, []);

    writeln(tag.toHexString!(LetterCase.lower));
    
    // // ubyte[keyBitSize/8] key = 0;
    // // string keyString = "key";
    // // foreach (i; 0..min(keyString.length, keyBitSize/8))
    // //     key[i] = cast(ubyte) keyString[i];

    // ubyte[keyBitSize/8] key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    
    // // ubyte[16] input = 0;
    // // string inputString = "The quick brown fox jumped over the lazy dog";
    // // foreach (i; 0..min(inputSize, inputSize))
    // //     input[i] = inputString[i];
    // ubyte[16] input = [0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a];

    // ubyte[16] output = 0;
    // aes_crypt_ecb(&ctx, false, input.ptr, output.ptr);

    // import std.stdio;
    // writeln(output.toHexString!(LetterCase.lower));
}

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

void shiftLeftInto(ubyte[] arrSource, ubyte[] arrDest)
{
    ubyte leftover = 0;
    foreach (i; 0..arrSource.length)
    {
        arrDest[i] = cast(ubyte)(arrSource[i] << 1) | leftover;
        leftover = (arrSource[i] & 0x80) >> 7; 
    }
}
unittest
{
    ubyte[4] source = [0x80, 0x01, 0x88, 0x00];
    ubyte[4] dest = void;
    shiftLeftInto(source[], dest[]);
    assert(dest[] == [0x00, 0x03, 0x10, 0x01]);
}


struct KeyCMAC(int blockSize)
{
    ubyte[blockSize] k1;
    ubyte[blockSize] k2;
}

template BlockCipher(int blockSize)
{
    alias BlockCipher = ubyte[blockSize] delegate(ref const(ubyte)[blockSize]);
}

auto getKeyCMAC(int blockSize)(scope BlockCipher!blockSize blockCipher, const(ubyte)[] key)
{
    static if (blockSize == 8)
        enum ubyte c = 0x1b;
    else static if (blockSize == 16)
        enum ubyte c = 0x87;
    else static assert(0);

    ubyte[blockSize] zeros = 0;
    auto k0 = blockCipher(zeros);

    ubyte[blockSize] k1 = void;
    shiftLeftInto(k0[], k1[]);
    if (k0[$-1] & 0x80)
        k1[] ^= c;

    ubyte[blockSize] k2 = void;
    shiftLeftInto(k1[], k2[]);
    if (k1[$-1] & 0x80)
        k2[] ^= c;

    return KeyCMAC!blockSize(k1, k2);
}

auto getTagCMAC(int blockSize)(scope BlockCipher!blockSize blockCipher, KeyCMAC!blockSize key, const(ubyte)[] message)
{
    ubyte[blockSize] mLast = void;
    // complete block
    if (message.length && message.length % blockSize == 0)
        mLast[] = key.k1[] ^ message[$ - blockSize..$];
    // incomplete block
    else
    {
        auto byteCount = message.length % blockSize;
        mLast[0..byteCount]     = key.k2[0..byteCount] ^ message[$ - byteCount..$];
        mLast[byteCount]        = key.k2[byteCount] ^ 1;
        mLast[byteCount + 1..$] = key.k2[byteCount + 1..$];
    }
    
    size_t messageIndex = 0;
    ubyte[blockSize] x = 0;
    ubyte[blockSize] y = void;

    auto numIters = message.length / blockSize;
    foreach (i; 0..numIters)
    {
        y[] = x[] ^ message[messageIndex..messageIndex + blockSize];
        x = blockCipher(y);
        messageIndex += blockSize;
    }

    y[] = mLast[] ^ x[];
    return blockCipher(y);
}