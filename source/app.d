import std.digest;
import std.digest.sha;
import std.range;
import std.string;

void main()
{
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
    const(ubyte)[] k;
    ubyte[blockSize] k1;
    ubyte[blockSize] k2;
}

auto getKeyCMAC(alias blockCipher, int blockSize, const(ubyte)[] c)(const(ubyte)[] key)
{
    ubyte[blockSize] zeros = 0;
    auto k0 = blockCipher(key, zeros[]);

    ubyte[blockSize] k1 = void;
    shiftLeftInto(k0[], k1[]);
    if (k0[$-1] & 0x80)
        k1[] ^= c[];

    ubyte[blockSize] k2 = void;
    shiftLeftInto(k1[], k2[]);
    if (k1[$-1] & 0x80)
        k2[] ^= c[];

    return KeyCMAC(k, k1, k2);    
}

auto getTagCMAC(alias blockCipher, int blockSize)(ref const(KeyCMAC!blockSize) key, const(ubyte)[] message)
{
    ubyte[blockSize] mLast = void;
    // complete block
    if (message.length % blockSize == 0)
        mLast[] = key.k1[] ^ message[$ - blockSize..$];
    // incomplete block
    else
    {
        auto byteCount = message.length % blockSize;
        mLast[0..byteCount]     = key.k2[0..byteCount] ^ message[$ - byteCount..$];
        mLast[byteCount]        = key.k2[byteCount] ^ 1;
        mLast[byteCount + 1..$] = key.k2[byteCount + 1..$];
    }
    
    int messageIndex = 0;
    ubyte[blockSize] x = 0;
    ubyte[blockSize] y = void;
    do 
    {
        y[] = x[] ^ message[messageIndex..messageIndex + blockSize];
        x = blockCipher(key.k, y[]);
    }
    while (messageIndex < message.length);

    y[] = mLast[] ^ x[];
    return blockCipher(key.k, y[]);
}