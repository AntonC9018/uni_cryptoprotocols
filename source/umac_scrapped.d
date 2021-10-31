module umac_scrapped;

static if (0)
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
            if (message.length <= l1KeyLength)
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

    ulong[2] l2Hash(in byte[l2KeyLength] key, const(ubyte)[] message)
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
        const ulong key_hi = cast(uint)(key >> 32);
        const ulong key_lo = cast(uint)(key);
        const ulong current_hi = cast(uint)(current >> 32);
        const ulong current_lo = cast(uint)(current);

        const ulong X = key_hi * current_lo + current_hi * key_lo;
        const ulong x_lo = cast(uint)(X);
        const ulong x_hi = cast(uint)(X >> 32);

        const ulong mystery = 59;
        const ulong T = x_lo << 32;
        ulong result = (key_hi * current_hi + x_hi) * mystery + key_lo * current_lo;

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