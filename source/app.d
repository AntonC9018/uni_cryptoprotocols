import std.digest;
import std.digest.sha;
import std.range;
import std.string;
import std.algorithm;

void main()
{
}


auto fromHexString(string source)
{
    import std.utf;
    import std.conv : to;
    return source.byCodeUnit.chunks(2).map!(c => c.to!ubyte(16));
}
unittest
{
    assert(equal(fromHexString("1234ABcd"), [0x12, 0x34, 0xab, 0xcd]));
}

void fromHexString(ubyte[] output, string source)
{
    assert(output.length == source.length / 2);
    foreach (i, b; fromHexString(source).enumerate)
        output[i] = b;
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
    if (k0[0] & 0x80)
        k1[15] ^= c;

    ubyte[blockSize] k2 = void;
    shiftLeftInto(k1[], k2[]);
    if (k1[0] & 0x80)
        k2[15] ^= c;

    return KeyCMAC!blockSize(k1, k2);
}

auto getTagCMAC(int blockSize)(scope BlockCipher!blockSize blockCipher, 
    ref const(KeyCMAC!blockSize) key, const(ubyte)[] message)
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
unittest
{
    import aes;

    // Test vectors: https://datatracker.ietf.org/doc/html/rfc4493#section-4
    enum keyBitSize = 128;
    ubyte[keyBitSize/8] key = void;
    fromHexString(key[], "2b7e151628aed2a6abf7158809cf4f3c");

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
    assert(doAes(zeros).toHexString!(LetterCase.lower) == "7df76b0c1ab899b33e42f047b91b546f");

    auto processedKey = getKeyCMAC!16(&doAes, key[]);
    assert(processedKey.k1.toHexString!(LetterCase.lower) == "fbeed618357133667c85e08f7236a8de");
    assert(processedKey.k2.toHexString!(LetterCase.lower) == "f7ddac306ae266ccf90bc11ee46d513b");

    ubyte[inputSize] tag;
    
    tag = getTagCMAC!16(&doAes, processedKey, []);
    assert(equal(tag[], fromHexString("bb1d6929e95937287fa37d129b756746")));

    tag = getTagCMAC!16(&doAes, processedKey, fromHexString("6bc1bee22e409f96e93d7e117393172a").array);
    assert(equal(tag[], fromHexString("070a16b46b4d4144f79bdd9dd04a287c")));

    tag = getTagCMAC!16(&doAes, processedKey, 
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