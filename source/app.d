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

    auto ctx = createEncryptionContext(key[]); 

    enum inputSize = 16;
    auto doAes(in ubyte[inputSize] input) { return cryptEcb(ctx, input[]); }

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

// struct UMAC(size_t aesBlockSize, size_t aesKeyLength)
// {
//     ubyte[aesKeyLength] 
// }

template UMAC(size_t aesBlockLength = 16, size_t aesKeyLength = 128 / 8, size_t umacTagLength = 8)
{
    import aes;
    enum umacKeyLength = 16;

    void deriveKey(ubyte[] outBuffer, in AESContext encryptionContext, byte streamIndex)
    {
        ubyte[aesBlockLength] inBuffer = 0;

        enum streamIndexIndex = aesBlockLength - 9;
        enum counterIndex = aesBlockLength - 1;
        inBuffer[streamIndexIndex] = streamIndex;
        inBuffer[counterIndex] = 1;

        while (outBuffer.length >= aesBlockLength) 
        {
            outBuffer[0..aesBlockLength] = encryptEcb(encryptionContext, inBuffer);
            outBuffer = outBuffer[aesBlockLength..$];
            inBuffer[counterIndex]++;
        }
        if (outBuffer.length > 0) 
            outBuffer[] = encryptEcb(encryptionContext, inBuffer)[0..outBuffer.length];
    }

    struct PadDerivationContext
    {
        ubyte[aesBlockLength] cachedAesOutput = void;
        ubyte[aesBlockLength] nonce = 0;
        AESContext!(Yes.encrypt) pseudoradomAesContext = void;

        void recomputeAesOutput()
        {
            cachedAesOutput = encryptEcb(pseudoradomAesContext, nonce);
        }
    }

    PadDerivationContext padDerivationContextInit(in AESContext!(Yes.encrypt) pseudorandomFunctionAesContext)
    {
        ubyte[umacKeyLength] pseudorandomKeyBuffer;
        
        // Initialization is done by encrypting an (almost) empty string 
        // with the given key (context).
        // The result will be used as the key.
        deriveKey(pseudorandomKeyBuffer[], pseudorandomFunctionAesContext, 0);

        PadDerivationContext result;
        result.pseudoradomAesContext = aes.createEncryptionContext(pseudorandomKeyBuffer);
        result.recomputeAesOutput();
        return result;
    }

    ref ubyte[umacTagLength] derivePad(ref return PadDerivationContext *padDerivationContext, in ubyte[8] nonce)
    {
        import math : max;
        enum int modForComputingIndex = aesBlockLength / umacTagLength;
        enum lowBitsMask = cast(ubyte) max(modForComputingIndex - 1, 0);

        static if (lowBitMask != 0)
            int index = nonce[$ - 1] & lowBitsMask;
        
        ubyte[4] tempNonceBytes = nonce[4..8];
        tempNonceBytes[3] &= ~lowBitsMask; // zero last bits

        // ref uint _uint(ref ubyte[4] bytes) { return (cast(ubyte[1]) bytes.ptr)[0]; }

        if (tempNonceBytes[0..4] != padDerivationContext.nonce[4..8] 
            || nonce[0..4] != padDerivationContext.nonce[0..4])
        {
            padDerivationContext.nonce[0..4] = nonce[0..4];
            padDerivationContext.nonce[4..8] = tempNonceBytes[0..4];
            padDerivationContext.recomputeAesOutput();
        }

        static if (umacTagLength == 4 || umacTagLength == 8)
        {
            size_t byteIndex = index * umacTagLength;
            return padDerivationContext.cachedAesOutput[byteIndex .. byteIndex + umacTagLength][0..umacTagLength];
        }
        else
        {
            return padDerivationContext.cachedAesOutput[0..umacTagLength];
        }
    }

    ubyte[umacTagLength] getTag(in ubyte[aesKeyLength] key, const(ubyte)[] message, PadDerivationContext* context, in ubyte[aesBlockLength] nonce)
    {
        auto hashedMessage = uhash(key, message);
        hashedMessage[] ^= derivePad(context, nonce)[];
        return hashedMessage;
    }

    // struct KeyData
    // {
    //     ubyte[
    // }
    enum l1KeyLength = 1024;
    enum l2KeyLength = 24;
    enum l3Key1Length = 64;
    enum l3Key2Length = 4;

    ubyte[umacTagLength] uhash(ubyte[aesKeyLength] key, const(ubyte)[] message)
    {
        // One internal iteration per 4 bytes of output
        enum numIters = umacTagLength / 4; 

        // Define total key needed for all iterations using KDF.
        // L1Key reuses most key material between iterations.
        ubyte[l1KeyLength + (numIters - 1) * 16] l1Key  = void;
        ubyte[numIters * l2KeyLength]            l2Key  = void;
        ubyte[numIters * l3Key1Length]           l3Key1 = void;
        ubyte[numIters * l3Key2Length]           l3Key2 = void;

        auto context = aes.createEncryptionContext(key);
        deriveKey(l1Key[], context);
        deriveKey(l2Key[], context);
        deriveKey(l3Key1[], context);
        deriveKey(l3Key2[], context);

        ubyte[umacTagLength] result;

        foreach (i; 0..numIters)
        {
            size_t l1KeyIndexStart = i * 16;
            auto A = l1Hash(l1Key[l1KeyIndexStart .. l1KeyIndexStart + l1KeyLength], message);

            import std.traits : ReturnType;
            ReturnType!l2Hash B = void;
            if (message.length <= l1KeySliceLength)
            {
                B[0 .. A.length] = A[];
                B[A.length .. $] = 0;
            }
            else
            {
                size_t l2KeyIndexStart = i * l2KeyLength;
                B = l2Hash(l2Key[l2KeyIndexStart .. l2KeyIndexStart + l2KeyLength], A);
            }

            size_t l3Key1IndexStart = i * l3Key1Length;
            size_t l3Key2IndexStart = i * l3Key2Length;
            auto C = l3Hash(
                l3Key1[l3Key1IndexStart .. l3Key1IndexStart + l3Key1Length], 
                l3Ley2[l3Key2IndexStart .. l3Key2IndexStart + l3Key2Length], B);

            result[i * C.length .. (i + 1) * C.length] = C[];
        }
        return result;
    }

    ulong[] l1Hash(in ubyte[l1KeyLength] key, const(ubyte)[] message)
    {
        assert(message.length != 0);
        auto t = ceilingDivide(message.length, l1KeyLength);

        // ubyte[l1KeyLength] intermediateResult;
        auto result = new ulong[](t);
        ulong lenIdk = l1KeyLength * 8;
        
        foreach (i; 0 .. (t - 1))
        {
            size_t messageIndexStart = i * l1KeyLength;
            ubyte[l1KeyLength] chunk = message[messageIndexStart .. messageIndexStart + l1KeyLength];
            maybeEndianSwap(cast(uint[]) chunk);
            ulong nextLong = nh(key, chunk) + lenIdk;
            result[i] = nextLong;
        }

        {
            lenIdk = message.length * 8;
            ubyte[l1KeyLength] chunk = void;
            size_t messageStartIndex = (t - 1) * l1KeyLength;
            chunk[0 .. message.length - messageStartIndex] = message[messageStartIndex .. $];
            chunk[message.length - messageStartIndex .. $] = 0;
            maybeEndianSwap(cast(uint[]) chunk[]);
            ulong lastLong = nh(key, chunk) + lenIdk;
            result[t - 1] = lastLong;
        }
        return result;
    }

    ulong nh(in ubyte[l1KeyLength] key, in ubyte[l1KeyLength] message)
    {
        ulong result = 0;
        auto key4 = cast(uint[l1KeyLength / 4]) key;
        auto message4 = cast(uint[l1KeyLength / 4]) message4;
        uint[l1KeyLength / 4] sums = key4[] + message4[];

        // This can be easily refactored to use simd instructions.
        foreach (i; iota(0, l1KeyLength / 4, 2))
            result += cast(ulong) sums[i] * cast(ulong) sums[i + 1];

        // return cast(ubyte[8]) &result[0..1];
        return result;
    }

    ubyte[16] l2Hash(in byte[l2KeyLength] key, const(ubyte)[] message)
    {
        ulong mask64  = 0x01ffffff01ffffff;
        ulong k64     = (cast(ulong[1]) key[0..8])[0] & mask64;
        ulong[2] k128 = cast(ulong[2]) key[8..24];
        enum p64 = 0xFFFFFFFF_FFFFFFC5;
        k128[] &= mask64;

        if (message.length <= 2^^17)
        {
            ulong y = poly64(cast(ulong) -2^^32, k64, p64); 
        }
    }

    // yoinked from https://github.com/openssh/openssh-portable/blob/0328a081f38c09d2d4d650e94461a47fb5eef536/umac.c#L797
    // But I do not understand wth it even does.
    ulong poly64(ulong current, ulong key, ulong data)
    {
        ulong key_hi = cast(uint)(key >> 32);
        ulong key_lo = cast(uint)(key);
        ulong current_hi = cast(uint)(current >> 32);
        ulong current_lo = cast(uint)(current);

        ulong X = key_hi * current_lo + current_hi * key_lo;
        ulong x_lo = cast(uint)(X);
        ulong x_hi = cast(uint)(X >> 32);

        const ulong mystery = 59;
        ulong result = key_hi * current_hi + x_hi;
        ulong result = result * mystery + key_lo * current_lo;
        ulong T = x_lo << 32;

        result += T;
        if (result < T)
            result += mystery;

        result += data;
        if (result < data)
            result += mystery;

        return result;
    }

    // tried implementing this, but it's just too overwhelming
    static if (0)
    auto poly(ulong wordLength8)(ulong[wordLength8] maxwordrange, ulong[wordLength8] k, ulong[] message)
    {
        static assert(wordLength8 == 1 || wordLength8 == 2);
        enum numBytes = wordLength8 * 8;

        static if (wordLength8 == 1)
        {
            static immutable(ulong)[1] prime = [0xFFFFFFFF_FFFFFFC5];
            static immutable(ulong)[1] offset = [-prime[0]]; 
        }
        else
        {
            static immutable(ulong)[2] prime = [0xFFFFFFFF_FFFFFF61, 0xFFFFFFFF_FFFFFFFF];
            static immutable(ulong)[2] offset = [-prime[0], ~prime[1]];
            assert((message.length & 1) == 0, "Message must be divisible by wordLength in multiples of 8 bytes.");
        }
        static immutable(ulong)[wordLength8] marker = prime[] - 1;

        size_t numChunks = message.length / wordLength8;

        ulong[wordLength8] result;
        result[0] = 1;
        foreach (i; iota(0, numChunks, wordLength8))
        {
            ulong[wordLength8] m = message[i .. i + wordLength8];
            // Just check the most significant bytes
            // Only check the other bytes if the most significat bytes were equal
            bool isGreaterOrEqual()
            {
                foreach_reverse (index, component; m)
                {
                    // If a more significat bit is greater (smaller), all the rest don't matter
                    if (component > maxwordrange[index])
                        return true;
                    if (component < maxwordrange[index])
                        return false;
                }
                return true; // All were equal
            }
            if (isGreaterOrEqual)
            {
                // TODO: Implement 128 bits. It's not that simple.
                // TODO: This simple thing I did won't work even for 64 bits, because it might overflow.
                result[] = (k[] * result[] + marker[]) % prime[];
                result[] = (k[] * result[] + (m[] - offset[])) % prime[];
            }
            else
            {
                result[] = (k[] * result[] + m[]) % prime[];
            }
        }
        return result;
    }

    // ulong polyMultiply(ulong a, ulong b, ulong prime)
    // {
    //     ulong result = 1;
    //     foreach (i; 0 .. ulong.sizeof * 8)
    //     {
    //         ulong currentBit = ((a >> i) & 1);
    //     }
    // }
}


void main()
{
    import aes;
    import std.stdio;

    enum keyBitSize = 128;
    enum inputSize = 16;

    ubyte[keyBitSize/8] key = void;
    auto ctx = createEncryptionContext(key);

    auto doAes(in ubyte[inputSize] input)
    {
        return ctx.cryptEcb(input);
    }

    // alias AesUMAC = UMAC!doAes;
    // ubyte[16] processedKey = void;
    // AesUMAC.getKey(processedKey[], 0);
    // writeln(processedKey);
}